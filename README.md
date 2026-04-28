# ec2ssh

`ec2ssh` is a small Go CLI that opens temporary SSH access to an EC2 instance,
starts a local `ssh` session, and removes the temporary security group rule when
the session exits.

By default it allows only your current public IPv4 address as a `/32` rule.
Existing SSH rules are left untouched, and cleanup only removes the rule this
tool created.

## Build

```sh
go mod tidy
go build -o ec2ssh .
```

## Usage

```sh
./ec2ssh \
  -profile my-aws-profile \
  -region us-east-1 \
  -instance-id i-0123456789abcdef0 \
  -user ec2-user \
  -key ~/.ssh/my-key.pem
```

You can select the EC2 instance with exactly one of these target flags:

```sh
./ec2ssh -instance-id i-0123456789abcdef0 -user ec2-user -key ~/.ssh/my-key.pem
./ec2ssh -ip 203.0.113.10 -user ec2-user -key ~/.ssh/my-key.pem
./ec2ssh -name web-prod-01 -user ec2-user -key ~/.ssh/my-key.pem
```

`-name` searches the EC2 `Name` tag and supports AWS wildcards, such as
`web-prod-*`. If an IP or name search matches multiple instances, the command
prints the matching instance IDs and asks you to rerun with `-instance-id`.

Useful flags:

- `-h`, `--help`: show command help.
- `-instance-id`: EC2 instance ID to connect to.
- `-ip`: EC2 public or private IPv4 address to search for.
- `-name`: EC2 `Name` tag to search for.
- `-profile`: AWS shared config/credentials profile. If omitted, the normal AWS
  provider chain is used, including `AWS_PROFILE`.
- `-region`: AWS region. If omitted, the profile/default region is used.
- `-cidr`: CIDR to open. If omitted, the tool detects your public IPv4 address
  via `https://checkip.amazonaws.com` and opens `<ip>/32`.
- `-sg-id`: security group to modify. If omitted, the first security group
  attached to the instance is used when a new rule is needed.
- `-port`: SSH port. Defaults to `22`.

The AWS identity must be allowed to call:

- `ec2:DescribeInstances`
- `ec2:DescribeSecurityGroups`
- `ec2:AuthorizeSecurityGroupIngress`
- `ec2:RevokeSecurityGroupIngress`
