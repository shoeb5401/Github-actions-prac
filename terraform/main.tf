terraform {
  backend "s3" {
    bucket = "dev-terraform-state-bucket-3084"
    key    = "${STAGE}.tfstate"
    region = "ap-south-1"
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

# EC2 Instance
resource "aws_instance" "writeonly_instance" {
  ami           = var.ami_id
  instance_type = var.instance_type
  key_name      = aws_key_pair.assignment.key_name
  security_groups = [aws_security_group.ssh_restricted.name]
 
 user_data = templatefile("${path.module}/../scripts/upload_user_data.sh.tpl",{ s3_bucket_name = var.s3_bucket_name })

  iam_instance_profile = aws_iam_instance_profile.writeonly_profile.name
  depends_on = [aws_iam_instance_profile.writeonly_profile,aws_s3_bucket.log_bucket]

  root_block_device {
    volume_size = var.volume_size
    volume_type = "gp3"
  }

  tags = {
    Name = "${var.stage}-writeonly-instance"
    Role = "writeonly"
  Stage = var.stage
  }
}

resource "aws_instance" "readonly_instance" {
  ami           = var.ami_id
  instance_type = var.instance_type
  key_name      = aws_key_pair.assignment.key_name
  security_groups = [aws_security_group.ssh_restricted.name]
  iam_instance_profile = aws_iam_instance_profile.readonly_profile.name
  depends_on = [aws_iam_instance_profile.readonly_profile,aws_s3_bucket.log_bucket]
  user_data = templatefile("${path.module}/../scripts/download_user_data.sh.tpl", {s3_bucket_name = var.s3_bucket_name})
  root_block_device {
    volume_size = var.volume_size
    volume_type = "gp3"
  }

  tags = {
    Name = "${var.stage}-readonly-instance"
    Role = "readonly"
  Stage = var.stage
  }
}
# Security Group
resource "aws_security_group" "ssh_restricted" {
  name        = "ssh-from-my-ip"
  description = "Allow SSH access from my IP only"

  ingress {
    description = "SSH from my IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.my_ip]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
  description = "Access Server from Outside"
  from_port   = 80
  to_port     = 80
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

}

# IAM Role for S3 Write-Only Access 
resource "aws_iam_role" "s3_readonly_role" {
  name = var.s3_readonly_role_name
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
}

resource "aws_iam_role_policy" "s3_readonly_policy" {
  name   = "S3ReadOnlyPolicy"
  role   = aws_iam_role.s3_readonly_role.id
  policy = data.aws_iam_policy_document.s3_readonly.json
}

# IAM Role for S3 Write-Only Access
resource "aws_iam_role" "s3_writeonly_role" {
  name = var.s3_writeonly_role_name
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
}

resource "aws_iam_role_policy" "s3_writeonly_policy" {
  name   = "S3WriteOnlyPolicy"
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
    actions   = ["s3:ListBucket", "s3:GetObject"]
    resources = ["arn:aws:s3:::*", "arn:aws:s3:::*/*"]
  }
}

# S3 WriteOnly Policy
data "aws_iam_policy_document" "s3_writeonly" {
  statement {
    actions   = ["s3:PutObject", "s3:CreateBucket"]
    resources = ["arn:aws:s3:::*", "arn:aws:s3:::*/*"]
  }

  statement {
    effect = "Deny"
    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]
    resources = ["arn:aws:s3:::*", "arn:aws:s3:::*/*"]
  }
}


# IAM Instance Profile for Write-Only Role
resource "aws_iam_instance_profile" "writeonly_profile" {
  name = "${var.stage}-writeonly-profile"
  role = aws_iam_role.s3_writeonly_role.name
}
# IAM Instance Profile for Read-only Role
resource "aws_iam_instance_profile" "readonly_profile" {
  name = "${var.stage}-readonly-profile"
  role = aws_iam_role.s3_readonly_role.name
}
# Private S3 Bucket
resource "aws_s3_bucket" "log_bucket" {
  bucket = var.s3_bucket_name

  tags = {
    Environment = var.stage
  }
    force_destroy = true  # Optional: only for auto-cleanup during destroy

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
      prefix = "app/logs/"
    }
  }
}


resource "aws_s3_bucket_public_access_block" "block_public" {
  bucket = aws_s3_bucket.log_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
