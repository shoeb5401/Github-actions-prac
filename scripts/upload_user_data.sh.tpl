#!/bin/bash
exec > /home/ubuntu/script.log 2>&1
set -e
set -x
# Accept input variables
stage="${stage}"
gh_pat="${gh_pat}"
repo_owner="${repo_owner}"
repo_name="${repo_name}"
s3_bucket_name="${s3_bucket_name}"
# Install dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install -y openjdk-21-jdk maven unzip
# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
aws --version
rm -rf awscliv2.zip ./aws/
# Clone configuration repo
cd /home/ubuntu
echo "GH_PAT length: $${#gh_pat}"
set +x # Prevent leaking token
echo "🔐 Cloning from private repo for stage: $$stage"
git clone "https://$${gh_pat}@github.com/$${repo_owner}/$${repo_name}.git" config-repo
set -x
# Clone and build app
git clone https://github.com/techeazy-consulting/techeazy-devops.git
cd techeazy-devops
mvn clean package
cd target
# Copy stage-specific config from config-repo
cp "/home/ubuntu/config-repo/application-$${stage}.yml" "/home/ubuntu/app-config.yml"
# Run the JAR with
nohup sudo java -jar techeazy-devops-0.0.1-SNAPSHOT.jar \
--spring.profiles.active=$${stage} \
--spring.config.additional-location=file:/home/ubuntu/app-config.yml &
# Create shutdown upload script
sudo tee /usr/local/bin/upload-script-log.sh > /dev/null <<EOF
#!/bin/bash
exec >> /var/log/upload-to-s3.log 2>&1
set -e
BUCKET_NAME="${s3_bucket_name}"
stage="${stage}"
LOG_FILE="/home/ubuntu/script.log"
S3_KEY="logs/\$${stage}/script.log"
if [ -f "\$$LOG_FILE" ]; then
 sleep 5
 aws s3 cp "\$$LOG_FILE" "s3://\$$BUCKET_NAME/\$$S3_KEY"
else
 echo "Log file not found: \$$LOG_FILE"
fi
EOF
sudo chmod +x /usr/local/bin/upload-script-log.sh
# Create systemd shutdown service
sudo tee /etc/systemd/system/upload-script-log.service > /dev/null <<EOF
[Unit]
Description=Upload script.log to S3 on shutdown
DefaultDependencies=no
Before=shutdown.target reboot.target halt.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/upload-script-log.sh
TimeoutStartSec=60
RemainAfterExit=true
[Install]
WantedBy=halt.target reboot.target shutdown.target
EOF
# Reload systemd and enable shutdown service
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable upload-script-log.service
# ✅ Upload log immediately after script finishes
aws s3 cp /home/ubuntu/script.log s3://${s3_bucket_name}/logs/${stage}/script.log || echo "Upload failed"
echo "✅ Script completed successfully"
exit 0