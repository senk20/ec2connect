# ec2connect
## ec2ssh / ec2sftp

`ec2ssh` and `ec2sftp` are small Go CLIs for connecting to an EC2 instance over
SSH or SFTP with temporary security group access.

Before connecting, the tool checks whether the instance allows the requested
port from your current public IPv4 address. If TCP port 22 is not already open
for that address, the tool adds a temporary `/32` ingress rule, starts a local
`ssh` or `sftp` session, and then removes only the rule it created when the
session exits.

Existing security group rules are left untouched.

## Build

```sh
go mod tidy
go build -o ec2ssh .
go build -o ec2sftp .
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
./ec2ssh -ip 203.0.113.10 -user ec2-user -key ~/.ssh/my-key.pem
./ec2sftp -name web-prod-01 -user ec2-user -key ~/.ssh/my-key.pem
```

`-ip` searches both public and private IPv4 addresses.

`-name` searches the EC2 `Name` tag and supports AWS wildcards, such as
`web-prod-*`. If an IP or name search matches multiple instances, the command
prints the matching instance IDs and asks you to rerun with `-instance-id`.

## Options

- `-h`, `--help`: show command help.
- `-instance-id`: EC2 instance ID to connect to.
- `-ip`: EC2 public or private IPv4 address to search for.
- `-name`: EC2 `Name` tag to search for.
- `-user`: SSH username, for example `ec2-user` or `ubuntu`. Required.
- `-key`: path to the private key passed to `ssh -i`.
- `-profile`: AWS shared config/credentials profile. If omitted, the normal AWS
  provider chain is used, including `AWS_PROFILE`.
- `-region`: AWS region. If omitted, the profile/default region is used.
- `-cidr`: CIDR to allow for SSH. If omitted, the tool detects your public IPv4
  address via `https://checkip.amazonaws.com` and opens `<ip>/32`.
- `-sg-id`: security group to modify. If omitted, the first attached security
  group is used when a new rule is needed.
- `-port`: SSH or SFTP port to open and connect to. Defaults to `22`.

## AWS Permissions

The AWS identity must be allowed to call:

- `ec2:DescribeInstances`
- `ec2:DescribeSecurityGroups`
- `ec2:AuthorizeSecurityGroupIngress`
- `ec2:RevokeSecurityGroupIngress`
