# 📘 DevOps EC2 Automation with Terraform (GitHub Actions Enabled)

This project provides a fully automated infrastructure deployment pipeline using **Terraform** and **GitHub Actions**. It provisions AWS EC2 instances, configures IAM roles, uploads logs to S3, fetches environment-based config files, and ensures application health using port checks.

---

## 📁 Project Structure

```
.
├── backend/
│   └── techeazy-devops-0.0.1-SNAPSHOT.jar     # Spring Boot JAR
├── config/
│   ├── application-dev.yml                   # Dev application config
│   └── application-prod.yml                  # Prod application config
├── scripts/
│   ├── upload_user_data.sh.tpl               # Write-only bootstrap
│   └── download_user_data.sh.tpl             # Read-only bootstrap
├── terraform/
│   ├── backend-dev.config                    # Dev backend config for state
│   ├── backend-prod.config                   # Prod backend config for state
│   ├── deploy.sh                             # Bash deploy script
│   ├── dev_config.tfvars                     # Dev config variables
│   ├── prod_config.tfvars                    # Prod config variables
│   ├── main.tf                               # Resources definition
│   ├── outputs.tf                            # Outputs
│   └── variables.tf                          # Variable definitions
├── .github/
│   └── workflows/
│       └── terraform-lifecycle.yml           # GitHub Actions workflow
├── .gitignore
└── README.md
```

---

## 🔧 Key Features

- 🌍 **Multi-Environment Deployments**: Dev & Prod support
- 🔐 **Secure SSH Key Generation**
- ☁️ **S3 Logging with Stage-Specific Folder Paths**
- 🛠️ **Config Separation per Stage** (`application-dev.yml`, `application-prod.yml`)
- 🌐 **Fetch Runtime Configs from GitHub (Public/Private)**
- 🔑 **GitHub Token Handling for Private Repos**
- 📡 **EC2 Health Checks via GitHub Actions**
- 🛡️ **IAM Role-Based Access Control**
- 🕒 **Auto Shutdown After 10 Minutes**
- 🖥️ **Live SSH Log Monitoring via CI**

---

## 🚀 GitHub Actions CI/CD

### Workflow Trigger

- Manual via `workflow_dispatch`
- Auto-deploy on push to `main` with tags:

  - `deploy-dev`
  - `deploy-prod`

### Workflow Behavior

1. Detects stage (`Dev`/`Prod`) and action (`apply`/`destroy`) using inputs or tag
2. Loads respective `.tfvars` and backend config
3. Initializes and validates Terraform with correct workspace
4. Applies or destroys infrastructure
5. Downloads the correct stage config (`application-dev.yml` or `application-prod.yml`) from a public/private GitHub repo
6. Provisions EC2 with config passed in
7. SSH into the EC2 using Terraform-generated key
8. Executes `tail -f /home/ubuntu/script.log` and exits gracefully
9. Pushes logs to:

   - `s3://<bucket>/logs/dev/...`
   - `s3://<bucket>/logs/prod/...`

10. Performs port 80 health check with up to 5 minutes retry

---

## 🧰 Prerequisites

- [Terraform CLI](https://developer.hashicorp.com/terraform/downloads)
- AWS CLI with configured profile
- GitHub Secrets:

  - `AWS_ACCESS_KEY`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`
  - `GH_PAT` (GitHub Personal Access Token for private repos)

```bash
export AWS_SHARED_CREDENTIALS_FILE="/path/to/credentials"
export AWS_PROFILE="your_profile"
```

- S3 bucket for Terraform state (Dev/Prod):

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
- Clones Spring Boot repo
- Downloads the config (`dev` or `prod`) from GitHub
- Places it under `config/` before running the app
- Starts JAR with `nohup`
- Adds shutdown logic:

  - Uploads `/home/ubuntu/script.log` to stage-based S3 folder
  - Shuts down after 10 mins

---

## 📤 Log Retrieval (Read-Only EC2)

```bash
aws configure --profile readonly
aws s3 ls s3://<bucket>/logs/dev/
aws s3 cp s3://<bucket>/logs/dev/script.log .
```

---

## 🔐 GitHub Config Handling

- **Supports both public and private GitHub repos** for config files
- Stage determines the access method:

  - `Dev`: fetches from public repo
  - `Prod`: requires GitHub PAT from Secrets

---

## 🖥️ SSH Log Monitoring (CI/CD)

After provisioning:

1. Terraform outputs `.pem` file path
2. GitHub Actions uses SSH to connect
3. Monitors `/home/ubuntu/script.log`
4. Handles timeout exit (code 124) gracefully

---

## 📎 Terraform Lifecycle Usage

```bash
# From GitHub UI:
# Trigger manually with: stage = Dev/Prod, action = apply/destroy

# From terminal:
cd terraform/
./deploy.sh Dev
```

---

## 🧪 Health Check Logic

- GitHub Actions retrieves EC2 public IP
- Verifies port 80 using `nc` + `curl`
- Retries for up to 5 minutes with graceful fail

---

## ✅ Tips

- Use `terraform destroy -var-file=prod_config.tfvars` to clean up
- Always set `.pem` permissions to `0400`
- Check `systemd` logs to verify shutdown upload succeeded

---

## 📌 Authors

Maintained by **shoeb qureshi** — feel free to contribute or open issues.
