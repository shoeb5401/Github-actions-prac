# 📘 DevOps EC2 Automation with Terraform (GitHub Actions Enabled)

This project provides a fully automated infrastructure deployment pipeline using **Terraform** and **GitHub Actions**. It provisions AWS EC2 instances, configures IAM roles, uploads logs to S3, and ensures application health using port checks.

---

## 📁 Project Structure

```
.
├── backend/
│   └── techeazy-devops-0.0.1-SNAPSHOT.jar     # Spring Boot JAR
├── scripts/
│   ├── upload_user_data.sh.tpl                # Write-only bootstrap
│   └── download_user_data.sh.tpl              # Read-only bootstrap
├── terraform/
│   ├── deploy.sh                              # Bash deploy script
│   ├── dev_config.tfvars                      # Dev config
│   ├── prod_config.tfvars                     # Prod config
│   ├── main.tf                                # Resources definition
│   ├── outputs.tf                             # Outputs
│   ├── variables.tf                           # Variable definitions
│   └── *.tfstate                              # Auto-generated state files
├── .github/workflows/
│   └── terraform-lifecycle.yml                # GitHub Actions workflow
└── README.md
```

---

## 🔧 Key Features

- 🌍 **Multi-Environment Deployments**: Supports `Dev` and `Prod`
- 🔐 **Secure SSH Key Generation**
- ☁️ **S3 Logging Lifecycle Policy (7 days retention)**
- 📡 **EC2 Health Checks via GitHub Actions**
- 🛡️ **IAM Role-Based Access Control**
- 🚦 **Auto Shutdown After 60 Minutes**
- 🖥️ **Live SSH Log Monitoring**

---

## 🚀 GitHub Actions CI/CD

### Workflow Trigger

- Manual via `workflow_dispatch`
- Auto-deploy on push to `main` with tags:

  - `deploy-dev`
  - `deploy-prod`

### Workflow Behavior

1. Detects stage (Dev/Prod) and action (apply/destroy)
2. Initializes Terraform with workspace logic
3. Validates and plans based on selected config
4. Applies or destroys infrastructure
5. Extracts EC2 public IP and waits for HTTP 200 response on port 80
6. SSH into the EC2 instance using the generated `.pem` key and runs:
   - `tail -f /home/ubuntu/script.log`
   - Exits gracefully and continues workflow

---

## 🧰 Prerequisites

- [Terraform CLI](https://developer.hashicorp.com/terraform/downloads)
- AWS CLI with credentials and profile set
- Github Secrets with same AWS credentials [AWS_ACCESS_KEY , AWS_SECRET_ACCESS_KEY , AWS_REGION]

```bash
export AWS_SHARED_CREDENTIALS_FILE="/path/to/credentials"
export AWS_PROFILE="your_profile"
```

- S3 bucket for Terraform state:

```bash
aws s3api create-bucket \
  --bucket dev-terraform-state-bucket-3084 \
  --region ap-south-1 \
  --create-bucket-configuration LocationConstraint=ap-south-1
```

---

## 🔐 IAM Roles

| Role        | Access Type | Scope    | Permissions                  |
| ----------- | ----------- | -------- | ---------------------------- |
| `writeonly` | Write-only  | EC2      | `s3:PutObject`               |
| `readonly`  | Read-only   | EC2/User | `s3:GetObject`, `ListBucket` |

---

## 🧠 EC2 Bootstrap Logic

**On Launch (Write-Only EC2):**

- Installs JDK, Maven, AWS CLI
- Clones & builds Spring Boot app
- Starts JAR with `nohup`
- Creates a shutdown hook:

  - Uploads `/home/ubuntu/script.log` to S3
  - Shuts down after 10 mins

---

## 📤 Log Retrieval (Read-Only EC2)

```bash
aws configure --profile readonly
aws s3 ls s3://<bucket>/app/logs/ 
aws s3 cp s3://<bucket>/app/logs/script.log . 
```

---

## 🔐 SSH Log Monitoring (CI/CD)

After infrastructure is deployed via GitHub Actions:

1. The `.pem` SSH private key is extracted from Terraform output
2. GitHub Actions securely connects to the EC2 instance via SSH
3. Runs `tail -f /var/log/script.log`
4. Exit code `124` from timeout is handled gracefully
5. Port 80 health check continues without interruption

No manual intervention is needed. The log monitoring is part of the CI workflow.

---

## 📎 Terraform Lifecycle Usage

```bash
# From GitHub UI
# Manually trigger with inputs: stage = Dev or Prod, action = apply/destroy

# From terminal (for bash deploy.sh)
cd terraform/
./deploy.sh Dev
```

---

## ✅ Tips

- Use `terraform destroy` to tear down resources
- Set `.pem` key permissions to `0400`
- Check systemd logs for shutdown log uploads

---

## 🧪 Health Check Logic

After apply, GitHub Actions will:

- Extract EC2 public IP from outputs
- Use `nc` and `curl` to validate port 80
- Retry for up to 5 minutes

---

## 📌 Authors

Maintained by **shoeb qureshi** — feel free to contribute or open issues.
