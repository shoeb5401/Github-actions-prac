variable "region" {
  description = "AWS Region"
  default     = "ap-south-1"
}

variable "instance_name" {
  description = "Name tag for EC2 instance"
  default     = "Devops-assignment"
}

variable "ami_id" {
  description = "AMI ID for Ubuntu"
  default     = "ami-0f918f7e67a3323f0"
}

variable "instance_type" {
  description = "EC2 instance type"
  default     = "t2.micro"
}

variable "key_name" {
  description = "Key pair name"
  default     = "Assignment"
}

variable "volume_size" {
  description = "Size of EBS volume in GB"
  default     = 10
}

variable "my_ip" {
  description = "My public IP address for connection"
  default     = "152.58.2.25/32"
}


variable "stage" {
  description = "Deployment Stage"
  default     = "Dev"
}

variable "s3_readonly_role_name" {
  description = "Name of the read-only role"
  type        = string
  default     = "s3-readonly-roles"
}

variable "s3_writeonly_role_name" {
  description = "Name of the write-only role"
  type        = string
  default     = "s3-writeonly-roles"
}


variable "s3_bucket_name" {
  description = "S3 bucket name for logs"
  type        = string

  validation {
    condition     = length(var.s3_bucket_name) > 0
    error_message = "S3 bucket name must not be empty."
  }
}


variable "gh_pat" {

  type = string
}


variable "repo_owner" {
  description = "GitHub repo owner"
  default     = "shoeb5401"
}

variable "repo_name" {
  description = "GitHub repo name"
  default     = "Secure-Repo-Config"
}

variable "alert_email" {
  description = "Email address for CloudWatch alarm notifications"
  type        = string
  default     = "shoeb.211618.et@mhssce.ac.in"

}