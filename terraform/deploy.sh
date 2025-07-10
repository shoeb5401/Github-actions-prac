#!/bin/bash

# Usage: ./deploy.sh Dev or ./deploy.sh Prod

# Check for input
if [ -z "$1" ]; then
  echo "❌ Error: No stage provided."
  echo "Usage: $0 [Dev|Prod]"
  exit 1
fi

STAGE=$1
STAGE_LOWER=$(echo "$STAGE" | tr '[:upper:]' '[:lower:]')
VARS_FILE="${STAGE_LOWER}_config.tfvars"

# Check if the .tfvars file exists
if [ ! -f "$VARS_FILE" ]; then
  echo "❌ Error: Config file '$VARS_FILE' not found."
  exit 1
fi

echo "✅ Deploying infrastructure for stage: $STAGE"
echo "📄 Using config file: $VARS_FILE"

# Initialize Terraform
terraform init -upgrade

# Apply Terraform config
terraform apply -var-file="$VARS_FILE" -auto-approve

echo "✅ Deployment for stage '$STAGE' completed."

