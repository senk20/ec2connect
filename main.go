package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type options struct {
	instanceID string
	ip         string
	name       string
	region     string
	profile    string
	user       string
	keyPath    string
	cidr       string
	sgID       string
	port       int32
}

type addedRule struct {
	sgID string
	cidr string
	port int32
}

type commandMode int

const (
	sshCommand commandMode = iota
	sftpCommand
	scpCommand
)

func main() {
	mode := getCommandMode()
	opts := parseFlags()
	if err := validateOptions(opts); err != nil {
		exitErr("%v", err)
	}
	if opts.user == "" {
		exitErr("missing required -user")
	}

	ctx := context.Background()
	cfg, err := loadAWSConfig(ctx, opts)
	if err != nil {
		exitErr("load AWS config: %v", err)
	}

	client := ec2.NewFromConfig(cfg)
	instance, err := findInstance(ctx, client, opts)
	if err != nil {
		exitErr("describe instance: %v", err)
	}

	target, err := instanceTarget(instance)
	if err != nil {
		exitErr("%v", err)
	}

	cidr := opts.cidr
	if cidr == "" {
		cidr, err = currentIPv4CIDR(ctx)
		if err != nil {
			exitErr("detect current public IP: %v", err)
		}
	}

	sgID, alreadyOpen, err := securityGroupForSSH(ctx, client, instance, opts.sgID, cidr, opts.port)
	if err != nil {
		exitErr("inspect security groups: %v", err)
	}

	var cleanup *addedRule
	if alreadyOpen {
		log.Printf("port %d is already open for %s", opts.port, cidr)
	} else {
		log.Printf("opening tcp/%d for %s on %s", opts.port, cidr, sgID)
		if err := authorizeAccess(ctx, client, sgID, cidr, opts.port, mode); err != nil {
			exitErr("open security group rule: %v", err)
		}
		cleanup = &addedRule{sgID: sgID, cidr: cidr, port: opts.port}
	}

	cleanupDone := make(chan struct{})
	go cleanupOnSignal(client, cleanup, cleanupDone)

	exitCode := 0
	if err := runConnection(target, opts, mode); err != nil {
		var sshExitErr *exec.ExitError
		if errors.As(err, &sshExitErr) {
			exitCode = sshExitErr.ExitCode()
		} else {
			log.Printf("connection failed: %v", err)
			exitCode = 1
		}
	}

	cleanupRule(context.Background(), client, cleanup)
	close(cleanupDone)
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func parseFlags() options {
	var opts options
	var help bool

	flag.Usage = printUsage
	flag.BoolVar(&help, "h", false, "show help")
	flag.BoolVar(&help, "help", false, "show help")
	flag.StringVar(&opts.instanceID, "instance-id", "", "EC2 instance ID to connect to")
	flag.StringVar(&opts.ip, "ip", "", "EC2 public or private IPv4 address to search for")
	flag.StringVar(&opts.name, "name", "", "EC2 Name tag to search for; supports AWS wildcards like web-*")
	flag.StringVar(&opts.region, "region", "", "AWS region; falls back to the profile/default region")
	flag.StringVar(&opts.profile, "profile", "", "AWS profile; falls back to AWS_PROFILE/default provider chain")
	flag.StringVar(&opts.user, "user", "", "SSH/SFTP username, for example ec2-user or ubuntu")
	flag.StringVar(&opts.keyPath, "key", "", "path to private key passed to ssh/sftp/scp -i")
	flag.StringVar(&opts.cidr, "cidr", "", "CIDR to allow for SSH/SFTP/SCP; defaults to your current public IPv4 /32")
	flag.StringVar(&opts.sgID, "sg-id", "", "security group to modify; defaults to the first attached group needing a rule")
	opts.port = 22
	flag.Var((*portFlag)(&opts.port), "port", "SSH/SFTP/SCP port to open and connect to")
	flag.Parse()
	if help {
		printUsage()
		os.Exit(0)
	}
	return opts
}

func validateOptions(opts options) error {
	selectors := 0
	for _, value := range []string{opts.instanceID, opts.ip, opts.name} {
		if value != "" {
			selectors++
		}
	}
	if selectors == 0 {
		return fmt.Errorf("missing target selector: provide one of -instance-id, -ip, or -name")
	}
	if selectors > 1 {
		return fmt.Errorf("provide only one target selector: -instance-id, -ip, or -name")
	}
	return nil
}

func printUsage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options]\n\n", os.Args[0])
	fmt.Fprintln(flag.CommandLine.Output(), "Open temporary SSH, SFTP, or SCP access to an EC2 instance, connect with ssh/sftp/scp, then remove the temporary rule.")
	fmt.Fprintln(flag.CommandLine.Output(), "\nOptions:")
	fmt.Fprintln(flag.CommandLine.Output(), "  -h, --help")
	fmt.Fprintln(flag.CommandLine.Output(), "    \tshow help")
	fmt.Fprintln(flag.CommandLine.Output(), "  -instance-id string")
	fmt.Fprintln(flag.CommandLine.Output(), "    \tEC2 instance ID to connect to")
	fmt.Fprintln(flag.CommandLine.Output(), "  -ip string")
	fmt.Fprintln(flag.CommandLine.Output(), "    \tEC2 public or private IPv4 address to search for")
	fmt.Fprintln(flag.CommandLine.Output(), "  -name string")
	fmt.Fprintln(flag.CommandLine.Output(), "    \tEC2 Name tag to search for; supports AWS wildcards like web-*")
	fmt.Fprintln(flag.CommandLine.Output(), "  -profile string")
	fmt.Fprintln(flag.CommandLine.Output(), "    \tAWS profile; falls back to AWS_PROFILE/default provider chain")
	fmt.Fprintln(flag.CommandLine.Output(), "  -region string")
	fmt.Fprintln(flag.CommandLine.Output(), "    \tAWS region; falls back to the profile/default region")
	fmt.Fprintln(flag.CommandLine.Output(), "  -user string")
	fmt.Fprintln(flag.CommandLine.Output(), "    \tSSH/SFTP/SCP username, for example ec2-user or ubuntu")
	fmt.Fprintln(flag.CommandLine.Output(), "  -key string")
	fmt.Fprintln(flag.CommandLine.Output(), "    \tpath to private key passed to ssh/sftp/scp -i")
	fmt.Fprintln(flag.CommandLine.Output(), "  -cidr string")
	fmt.Fprintln(flag.CommandLine.Output(), "    \tCIDR to allow for SSH/SFTP/SCP; defaults to your current public IPv4 /32")
	fmt.Fprintln(flag.CommandLine.Output(), "  -sg-id string")
	fmt.Fprintln(flag.CommandLine.Output(), "    \tsecurity group to modify; defaults to the first attached group needing a rule")
	fmt.Fprintln(flag.CommandLine.Output(), "  -port value")
	fmt.Fprintln(flag.CommandLine.Output(), "    \tSSH/SFTP/SCP port to open and connect to (default 22)")
}

type portFlag int32

func (f *portFlag) String() string {
	return fmt.Sprintf("%d", *f)
}

func (f *portFlag) Set(value string) error {
	var parsed int
	if _, err := fmt.Sscanf(value, "%d", &parsed); err != nil {
		return err
	}
	if parsed < 1 || parsed > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	*f = portFlag(parsed)
	return nil
}

func loadAWSConfig(ctx context.Context, opts options) (aws.Config, error) {
	loadOpts := []func(*config.LoadOptions) error{}
	if opts.profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(opts.profile))
	}
	if opts.region != "" {
		loadOpts = append(loadOpts, config.WithRegion(opts.region))
	}
	return config.LoadDefaultConfig(ctx, loadOpts...)
}

func findInstance(ctx context.Context, client *ec2.Client, opts options) (types.Instance, error) {
	switch {
	case opts.instanceID != "":
		return getInstanceByID(ctx, client, opts.instanceID)
	case opts.ip != "":
		return getInstanceByIP(ctx, client, opts.ip)
	case opts.name != "":
		return getSingleInstanceByFilters(ctx, client, "Name tag "+opts.name, []types.Filter{
			{Name: aws.String("instance-state-name"), Values: []string{"pending", "running", "stopping", "stopped"}},
			{Name: aws.String("tag:Name"), Values: []string{opts.name}},
		})
	default:
		return types.Instance{}, fmt.Errorf("no target selector provided")
	}
}

func getInstanceByIP(ctx context.Context, client *ec2.Client, ip string) (types.Instance, error) {
	publicMatches, err := describeInstancesByFilters(ctx, client, []types.Filter{
		{Name: aws.String("instance-state-name"), Values: []string{"pending", "running", "stopping", "stopped"}},
		{Name: aws.String("ip-address"), Values: []string{ip}},
	})
	if err != nil {
		return types.Instance{}, err
	}
	privateMatches, err := describeInstancesByFilters(ctx, client, []types.Filter{
		{Name: aws.String("instance-state-name"), Values: []string{"pending", "running", "stopping", "stopped"}},
		{Name: aws.String("private-ip-address"), Values: []string{ip}},
	})
	if err != nil {
		return types.Instance{}, err
	}
	return singleInstance("IP address "+ip, dedupeInstances(append(publicMatches, privateMatches...)))
}

func getInstanceByID(ctx context.Context, client *ec2.Client, instanceID string) (types.Instance, error) {
	out, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return types.Instance{}, err
	}
	for _, reservation := range out.Reservations {
		for _, instance := range reservation.Instances {
			return instance, nil
		}
	}
	return types.Instance{}, fmt.Errorf("instance %s not found", instanceID)
}

func getSingleInstanceByFilters(ctx context.Context, client *ec2.Client, description string, filters []types.Filter) (types.Instance, error) {
	matches, err := describeInstancesByFilters(ctx, client, filters)
	if err != nil {
		return types.Instance{}, err
	}
	return singleInstance(description, matches)
}

func singleInstance(description string, matches []types.Instance) (types.Instance, error) {
	switch len(matches) {
	case 0:
		return types.Instance{}, fmt.Errorf("no instance found for %s", description)
	case 1:
		return matches[0], nil
	default:
		return types.Instance{}, fmt.Errorf("%d instances found for %s; use -instance-id to choose one: %s", len(matches), description, instanceSummaries(matches))
	}
}

func dedupeInstances(instances []types.Instance) []types.Instance {
	seen := map[string]bool{}
	deduped := make([]types.Instance, 0, len(instances))
	for _, instance := range instances {
		id := aws.ToString(instance.InstanceId)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		deduped = append(deduped, instance)
	}
	return deduped
}

func describeInstancesByFilters(ctx context.Context, client *ec2.Client, filters []types.Filter) ([]types.Instance, error) {
	var instances []types.Instance
	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{
		Filters: filters,
	})
	for paginator.HasMorePages() {
		out, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, reservation := range out.Reservations {
			instances = append(instances, reservation.Instances...)
		}
	}
	return instances, nil
}

func instanceSummaries(instances []types.Instance) string {
	summaries := make([]string, 0, len(instances))
	for _, instance := range instances {
		summaries = append(summaries, fmt.Sprintf("%s(%s)", aws.ToString(instance.InstanceId), instanceName(instance)))
	}
	return strings.Join(summaries, ", ")
}

func instanceName(instance types.Instance) string {
	for _, tag := range instance.Tags {
		if aws.ToString(tag.Key) == "Name" {
			return aws.ToString(tag.Value)
		}
	}
	return "no Name tag"
}

func instanceTarget(instance types.Instance) (string, error) {
	if aws.ToString(instance.PublicDnsName) != "" {
		return aws.ToString(instance.PublicDnsName), nil
	}
	if aws.ToString(instance.PublicIpAddress) != "" {
		return aws.ToString(instance.PublicIpAddress), nil
	}
	return "", fmt.Errorf("instance has no public DNS name or public IPv4 address")
}

func currentIPv4CIDR(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://checkip.amazonaws.com", nil)
	if err != nil {
		return "", err
	}
	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("unexpected status from checkip.amazonaws.com: %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return "", fmt.Errorf("got non-IPv4 address %q; pass -cidr explicitly", ip)
	}
	return ip + "/32", nil
}

func securityGroupForSSH(ctx context.Context, client *ec2.Client, instance types.Instance, requestedSGID string, cidr string, port int32) (string, bool, error) {
	attached := attachedSecurityGroupIDs(instance)
	if len(attached) == 0 {
		return "", false, fmt.Errorf("instance has no attached security groups")
	}
	if requestedSGID != "" && !contains(attached, requestedSGID) {
		return "", false, fmt.Errorf("security group %s is not attached to instance %s", requestedSGID, aws.ToString(instance.InstanceId))
	}

	out, err := client.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		GroupIds: attached,
	})
	if err != nil {
		return "", false, err
	}

	for _, sg := range out.SecurityGroups {
		if requestedSGID != "" && aws.ToString(sg.GroupId) != requestedSGID {
			continue
		}
		if permissionAllowsCIDR(sg.IpPermissions, cidr, port) {
			return aws.ToString(sg.GroupId), true, nil
		}
	}

	if requestedSGID != "" {
		return requestedSGID, false, nil
	}
	return attached[0], false, nil
}

func attachedSecurityGroupIDs(instance types.Instance) []string {
	ids := make([]string, 0, len(instance.SecurityGroups))
	for _, sg := range instance.SecurityGroups {
		if aws.ToString(sg.GroupId) != "" {
			ids = append(ids, aws.ToString(sg.GroupId))
		}
	}
	return ids
}

func permissionAllowsCIDR(permissions []types.IpPermission, cidr string, port int32) bool {
	targetIP, targetNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	for _, permission := range permissions {
		if aws.ToString(permission.IpProtocol) != "tcp" {
			continue
		}
		if aws.ToInt32(permission.FromPort) > port || aws.ToInt32(permission.ToPort) < port {
			continue
		}
		for _, ipRange := range permission.IpRanges {
			_, ruleNet, err := net.ParseCIDR(aws.ToString(ipRange.CidrIp))
			if err != nil {
				continue
			}
			if ruleNet.Contains(targetIP) && ruleNet.Contains(lastIP(targetNet)) {
				return true
			}
		}
	}
	return false
}

func lastIP(ipNet *net.IPNet) net.IP {
	ip := ipNet.IP.To4()
	if ip == nil {
		return nil
	}
	mask := ipNet.Mask
	last := make(net.IP, len(ip))
	for i := range ip {
		last[i] = ip[i] | ^mask[i]
	}
	return last
}

func authorizeAccess(ctx context.Context, client *ec2.Client, sgID string, cidr string, port int32, mode commandMode) error {
	description := "temporary ec2ssh access"
	if mode == sftpCommand {
		description = "temporary ec2sftp access"
	}
	if mode == scpCommand {
		description = "temporary ec2scp access"
	}
	_, err := client.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: aws.String(sgID),
		IpPermissions: []types.IpPermission{{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(port),
			ToPort:     aws.Int32(port),
			IpRanges: []types.IpRange{{
				CidrIp:      aws.String(cidr),
				Description: aws.String(description),
			}},
		}},
	})
	if err != nil && strings.Contains(err.Error(), "InvalidPermission.Duplicate") {
		return nil
	}
	return err
}

func getCommandMode() commandMode {
	name := filepath.Base(os.Args[0])
	name = strings.TrimSuffix(name, filepath.Ext(name))
	if strings.EqualFold(name, "ec2sftp") {
		return sftpCommand
	}
	if strings.EqualFold(name, "ec2scp") {
		return scpCommand
	}
	return sshCommand
}

func runConnection(target string, opts options, mode commandMode) error {
	args := []string{}
	if opts.keyPath != "" {
		args = append(args, "-i", opts.keyPath)
	}
	if opts.port != 22 {
		portArg := "-p"
		if mode == sftpCommand || mode == scpCommand {
			portArg = "-P"
		}
		args = append(args, portArg, fmt.Sprintf("%d", opts.port))
	}

	program := "ssh"
	if mode == sftpCommand {
		program = "sftp"
	}
	if mode == scpCommand {
		program = "scp"
	}

	if mode == scpCommand {
		scpArgs := flag.Args()
		if len(scpArgs) < 2 {
			return fmt.Errorf("scp requires source and destination arguments")
		}
		if !hasRemoteSpec(scpArgs[0]) && !hasRemoteSpec(scpArgs[len(scpArgs)-1]) {
			scpArgs[len(scpArgs)-1] = fmt.Sprintf("%s@%s:%s", opts.user, target, scpArgs[len(scpArgs)-1])
		}
		args = append(args, scpArgs...)
	} else {
		args = append(args, fmt.Sprintf("%s@%s", opts.user, target))
		args = append(args, flag.Args()...)
	}

	cmd := exec.Command(program, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func hasRemoteSpec(arg string) bool {
	return strings.Contains(arg, ":")
}

func cleanupOnSignal(client *ec2.Client, cleanup *addedRule, cleanupDone <-chan struct{}) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		log.Printf("received %s; cleaning up", sig)
		cleanupRule(context.Background(), client, cleanup)
		os.Exit(130)
	case <-cleanupDone:
		return
	}
}

func cleanupRule(ctx context.Context, client *ec2.Client, rule *addedRule) {
	if rule == nil {
		return
	}
	log.Printf("removing tcp/%d for %s from %s", rule.port, rule.cidr, rule.sgID)
	_, err := client.RevokeSecurityGroupIngress(ctx, &ec2.RevokeSecurityGroupIngressInput{
		GroupId: aws.String(rule.sgID),
		IpPermissions: []types.IpPermission{{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int32(rule.port),
			ToPort:     aws.Int32(rule.port),
			IpRanges: []types.IpRange{{
				CidrIp: aws.String(rule.cidr),
			}},
		}},
	})
	if err != nil && !strings.Contains(err.Error(), "InvalidPermission.NotFound") {
		log.Printf("cleanup failed: %v", err)
	}
}

func runSSH(target string, opts options) error {
	args := []string{}
	if opts.keyPath != "" {
		args = append(args, "-i", opts.keyPath)
	}
	if opts.port != 22 {
		args = append(args, "-p", fmt.Sprintf("%d", opts.port))
	}
	args = append(args, fmt.Sprintf("%s@%s", opts.user, target))

	cmd := exec.Command("ssh", args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func exitErr(format string, args ...any) {
	log.Printf(format, args...)
	os.Exit(1)
}
