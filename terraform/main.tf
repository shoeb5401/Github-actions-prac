terraform {
  backend "s3" {
    # bucket, key, and region will be injected via -backend-config
  }
}

provider "aws" {
  region = var.region
}

# Generate SSH Key Pair
resource "tls_private_key" "assignment" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_file" "private_key" {
  content         = tls_private_key.assignment.private_key_pem
  filename        = "${path.module}/${var.key_name}.pem"
  file_permission = "0400"
}

resource "aws_key_pair" "assignment" {
  key_name   = var.key_name
  public_key = tls_private_key.assignment.public_key_openssh
}

# EC2 Instance - Write Only (with CloudWatch monitoring)
resource "aws_instance" "writeonly_instance" {
  ami             = var.ami_id
  instance_type   = var.instance_type
  key_name        = aws_key_pair.assignment.key_name
  security_groups = [aws_security_group.ssh_restricted.name]

  user_data = templatefile("${path.module}/../scripts/upload_user_data.sh.tpl", {
    s3_bucket_name = var.s3_bucket_name,
    stage          = lower(var.stage),
    gh_pat         = var.gh_pat,
    repo_owner     = var.repo_owner,
    repo_name      = var.repo_name
  })

  iam_instance_profile = aws_iam_instance_profile.writeonly_profile.name
  depends_on           = [aws_iam_instance_profile.writeonly_profile, aws_s3_bucket.log_bucket]

  root_block_device {
    volume_size = var.volume_size
    volume_type = "gp3"
  }

  tags = {
    Name  = "${var.stage}-writeonly-instance"
    Role  = "writeonly"
    Stage = var.stage
  }
}

# EC2 Instance - Read Only 
resource "aws_instance" "readonly_instance" {
  ami                  = var.ami_id
  instance_type        = var.instance_type
  key_name             = aws_key_pair.assignment.key_name
  security_groups      = [aws_security_group.ssh_restricted.name]
  iam_instance_profile = aws_iam_instance_profile.readonly_profile.name
  depends_on           = [aws_iam_instance_profile.readonly_profile, aws_s3_bucket.log_bucket]

  user_data = templatefile("${path.module}/../scripts/download_user_data.sh.tpl", {
    s3_bucket_name = var.s3_bucket_name,
    stage          = lower(var.stage)
  })

  root_block_device {
    volume_size = var.volume_size
    volume_type = "gp3"
  }

  tags = {
    Name  = "${var.stage}-readonly-instance"
    Role  = "readonly"
    Stage = var.stage
  }
}

# Security Group
resource "aws_security_group" "ssh_restricted" {
  name        = "ssh-from-my-ip-${var.stage}"
  description = "Allow SSH access from my IP only"

  ingress {
    description = "SSH from my IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  ingress {
    description = "Access Server from Outside"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name  = "ssh-restricted-${var.stage}"
    Stage = var.stage
  }
}

# IAM Role for S3 Read-Only Access 
resource "aws_iam_role" "s3_readonly_role" {
  name               = "${var.s3_readonly_role_name}-${var.stage}"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json

  tags = {
    Stage = var.stage
  }
}

resource "aws_iam_role_policy" "s3_readonly_policy" {
  name   = "S3ReadOnlyPolicy-${var.stage}"
  role   = aws_iam_role.s3_readonly_role.id
  policy = data.aws_iam_policy_document.s3_readonly.json
}

# IAM Role for S3 Write-Only Access + CloudWatch permissions
resource "aws_iam_role" "s3_writeonly_role" {
  name               = "${var.s3_writeonly_role_name}-${var.stage}"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json

  tags = {
    Stage = var.stage
  }
}

resource "aws_iam_role_policy" "s3_writeonly_policy" {
  name   = "S3WriteOnlyPolicy-${var.stage}"
  role   = aws_iam_role.s3_writeonly_role.id
  policy = data.aws_iam_policy_document.s3_writeonly.json
}

# Assume EC2 trust policy
data "aws_iam_policy_document" "assume_ec2" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# S3 ReadOnly Policy
data "aws_iam_policy_document" "s3_readonly" {
  statement {
    actions = ["s3:ListBucket", "s3:GetObject"]
    resources = [
      aws_s3_bucket.log_bucket.arn,
      "${aws_s3_bucket.log_bucket.arn}/*"
    ]
  }
}

# S3 WriteOnly Policy + CloudWatch permissions
data "aws_iam_policy_document" "s3_writeonly" {
  statement {
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.log_bucket.arn}/*"
    ]
  }

  statement {
    effect = "Deny"
    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.log_bucket.arn,
      "${aws_s3_bucket.log_bucket.arn}/*"
    ]
  }

  # CloudWatch Logs permissions for writeonly instance only
  statement {
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
      "logs:DescribeLogGroups"
    ]
    resources = [
      "arn:aws:logs:${var.region}:*:log-group:/aws/ec2/script-logs",
      "arn:aws:logs:${var.region}:*:log-group:/aws/ec2/script-logs:*"
    ]
  }

  # EC2 describe permissions for CloudWatch agent
  statement {
    actions = [
      "ec2:DescribeVolumes",
      "ec2:DescribeTags"
    ]
    resources = ["*"]
  }
}

# IAM Instance Profile for Write-Only Role
resource "aws_iam_instance_profile" "writeonly_profile" {
  name = "${var.stage}-writeonly-profile"
  role = aws_iam_role.s3_writeonly_role.name

  tags = {
    Stage = var.stage
  }
}

# IAM Instance Profile for Read-only Role
resource "aws_iam_instance_profile" "readonly_profile" {
  name = "${var.stage}-readonly-profile"
  role = aws_iam_role.s3_readonly_role.name

  tags = {
    Stage = var.stage
  }
}

# Attach CloudWatch Agent policy to write-only role ONLY
resource "aws_iam_role_policy_attachment" "writeonly_cw_agent" {
  role       = aws_iam_role.s3_writeonly_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Private S3 Bucket
resource "aws_s3_bucket" "log_bucket" {
  bucket = var.s3_bucket_name

  tags = {
    Environment = var.stage
    Purpose     = "Application logs storage"
  }
  force_destroy = true
}

# S3 Bucket Lifecycle Configuration
resource "aws_s3_bucket_lifecycle_configuration" "log_lifecycle" {
  bucket = aws_s3_bucket.log_bucket.id

  rule {
    id     = "delete-logs-after-7-days"
    status = "Enabled"

    expiration {
      days = 7
    }

    filter {
      prefix = "logs/"
    }
  }
}

# S3 Bucket Public Access Block
resource "aws_s3_bucket_public_access_block" "block_public" {
  bucket = aws_s3_bucket.log_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}