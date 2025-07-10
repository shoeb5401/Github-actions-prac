# 🚀 DevOps EC2 Automation with Terraform

This project automates the provisioning of EC2 instances on AWS using Terraform. It supports multi-environment deployments (`Dev`, `Prod`) and securely deploys a Spring Boot application (`techeazy-devops`). It includes SSH key pair creation, auto-shutdown logic, and automated log uploads to a private S3 bucket using IAM roles.

---

## 📁 Project Structure

```
.
├── backend/
│   └── techeazy-devops-0.0.1-SNAPSHOT.jar     # Compiled Spring Boot JAR
├── README.md                                  # Project documentation
├── scripts/
│   ├── upload_user_data.sh.tpl                # EC2 bootstrap script for log upload (write-only)
│   └── download_user_data.sh.tpl              # EC2 bootstrap script for log download (read-only)
└── terraform/
    ├── deploy.sh                              # Stage-aware deployment script
    ├── dev_config.tfvars                      # Dev environment config
    ├── prod_config.tfvars                     # Prod environment config
    ├── main.tf                                # Terraform resources
    ├── outputs.tf                             # Terraform outputs
    ├── variables.tf                           # Input variable definitions
    ├── terraform.tfstate                      # Terraform state (auto-generated)
    └── terraform.tfstate.backup               # Backup state (auto-generated)
```

---

## ⚙️ Key Features

* ✅ **Multi-Environment Support**: Seamlessly deploy to `Dev` or `Prod` using stage-aware configs.
* 🔐 **SSH Key Pair Generation**: 4096-bit RSA keys generated and saved locally.
* 🛡️ **Restricted Security Group**:

  * SSH access limited to your public IP
  * Open port 80 for HTTP traffic
* 🖥️ **Dual EC2 Deployment**:

  * **Write-only instance** uploads logs to S3
  * **Read-only instance** can securely download and view logs
* 💾 **Custom EBS, AMI, and instance type** based on environment
* ☁️ **S3 Bucket Lifecycle Policy**: Auto-deletes logs older than 7 days
* 📜 **Fully Automated App Setup**:

  * Installs dependencies
  * Clones and builds Spring Boot app
  * Runs app in background using `nohup`
* ☁️ **S3 Upload on Shutdown**:

  * Script and systemd service ensures graceful upload of logs to S3
* ⏱️ **Auto-Termination**: Instance shuts down automatically after 60 minutes to save cost

---

## 🧰 Prerequisites

* [Terraform](https://developer.hashicorp.com/terraform/downloads)
* AWS credentials configured in default or custom profile

```bash
export AWS_SHARED_CREDENTIALS_FILE="/path/to/credentials"
export AWS_PROFILE="your_profile_name"
```

* Add your public IP in `*.tfvars` file (Optional, for SSH access)

---

## 🧱 IAM Roles & Access

| Role        | Access Type | Attached To       | Permissions                     |
| ----------- | ----------- | ----------------- | ------------------------------- |
| `writeonly` | Write-only  | EC2 instance      | `s3:PutObject` only             |
| `readonly`  | Read-only   | EC2 instance/user | `s3:GetObject`, `s3:ListBucket` |

* IAM policies prevent privilege escalation (write role cannot read)
* IAM instance profiles are used to attach roles to EC2 securely

---

## 🚀 Deploying Infrastructure & App

Run the stage-specific deployment script:

```bash
cd terraform/
./deploy.sh Dev     # or ./deploy.sh Prod
```

This will:

* Inject correct values into `user_data.sh.tpl`
* Provision EC2, S3, IAM, and networking
* Launch the app and enable automated log handling

---

## 🔧 EC2 Bootstrap (user\_data)

### Actions Performed (write-only EC2):

* System update + install: JDK 21, Maven, AWS CLI
* Clone and build app from GitHub
* Run `.jar` in background
* Configure `systemd` shutdown hook to:

  * Upload `/home/ubuntu/script.log` to S3
  * Auto-shutdown after 60 minutes

```bash
aws s3 cp /home/ubuntu/script.log s3://<bucket-name>/app/logs/
```

---

## 🔎 Viewing Logs from S3

Use your `readonly` credentials or EC2 instance to list and download logs:

```bash
aws configure --profile readonly
aws s3 ls s3://<your-bucket-name>/app/logs/ --profile readonly
aws s3 cp s3://<your-bucket-name>/app/logs/script.log . --profile readonly
```

> Ensure that `readonly` IAM role or profile is used to avoid unauthorized access.

---


## 💡 Tips

* For **secure key management**, `.pem` files are saved locally with `0400` permissions.
* Enable logging in `upload-script-log.service` to debug uploads on shutdown.
* Use `terraform destroy` to clean up infra (includes force destroy on bucket).

---

