# ec2connect
## ec2ssh / ec2sftp / ec2scp

`ec2ssh`, `ec2sftp`, and `ec2scp` are small Go CLIs for connecting to an EC2 instance over
SSH, SFTP, or SCP with temporary security group access.

Before connecting, the tool checks whether the instance allows the requested
port from your current public IPv4 address. If TCP port 22 is not already open
for that address, the tool adds a temporary `/32` ingress rule, starts a local
`ssh`, `sftp`, or `scp` session, and then removes only the rule it created when the
session exits.

Existing security group rules are left untouched.

## Build

```sh
go mod tidy
go build -o ec2ssh .
go build -o ec2sftp .
go build -o ec2scp .
```

## Usage

Select the EC2 instance with exactly one of `-instance-id`, `-ip`, or `-name`.

```sh
./ec2ssh \
  -profile my-aws-profile \
  -region us-east-1 \
  -instance-id i-0123456789abcdef0 \
  -user ec2-user \
  -key ~/.ssh/my-key.pem
```

Examples:

```sh
./ec2ssh -instance-id i-0123456789abcdef0 -user ec2-user -key ~/.ssh/my-key.pem
./ec2sftp -instance-id i-0123456789abcdef0 -user ec2-user -key ~/.ssh/my-key.pem
./ec2scp -instance-id i-0123456789abcdef0 -user ec2-user -key ~/.ssh/my-key.pem /local/path /remote/path
./ec2ssh -ip 203.0.113.10 -user ec2-user -key ~/.ssh/my-key.pem
./ec2sftp -name web-prod-01 -user ec2-user -key ~/.ssh/my-key.pem
```

`-ip` searches both public and private IPv4 addresses.

`-name` searches the EC2 `Name` tag and supports AWS wildcards, such as
`web-prod-*`. If an IP or name search matches multiple instances, the command
prints the matching instance IDs and asks you to rerun with `-instance-id`.

For `ec2scp`, if neither source nor destination uses `host:path` syntax, the
last argument is treated as the EC2 target path and is automatically prefixed
with `user@<ec2-host>:`.

If you explicitly supply a remote destination in `user@host:path` form, the
command passes it through unchanged and does not add another `user@host`
argument.

## Options

- `-h`, `--help`: show command help.
- `-instance-id`: EC2 instance ID to connect to.
- `-ip`: EC2 public or private IPv4 address to search for.
- `-name`: EC2 `Name` tag to search for.
- `-user`: SSH/SFTP/SCP username, for example `ec2-user` or `ubuntu`. Required.
- `-key`: path to the private key passed to `ssh/sftp/scp -i`.
- `-profile`: AWS shared config/credentials profile. If omitted, the normal AWS
  provider chain is used, including `AWS_PROFILE`.
- `-region`: AWS region. If omitted, the profile/default region is used.
- `-cidr`: CIDR to allow for SSH/SFTP/SCP. If omitted, the tool detects your public IPv4
  address via `https://checkip.amazonaws.com` and opens `<ip>/32`.
- `-sg-id`: security group to modify. If omitted, the first attached security
  group is used when a new rule is needed.
- `-port`: SSH/SFTP/SCP port to open and connect to. Defaults to `22`.

## AWS Permissions

The AWS identity must be allowed to call:

- `ec2:DescribeInstances`
- `ec2:DescribeSecurityGroups`
- `ec2:AuthorizeSecurityGroupIngress`
- `ec2:RevokeSecurityGroupIngress`
