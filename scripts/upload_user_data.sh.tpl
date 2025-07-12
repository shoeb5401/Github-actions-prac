#!/bin/bash

exec > /home/ubuntu/script.log 2>&1
set -x

# Install dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install -y openjdk-21-jdk maven unzip

# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
aws --version
rm -rf awscliv2.zip ./aws/

# Clone and build app
cd /home/ubuntu
git clone https://github.com/techeazy-consulting/techeazy-devops.git
cd techeazy-devops
mvn clean package
cd target

# Run the JAR with logging
 nohup sudo java -jar techeazy-devops-0.0.1-SNAPSHOT.jar --server.port=80 &

# Create shutdown upload script
cat <<EOF | sudo tee /usr/local/bin/upload-script-log.sh > /dev/null
#!/bin/bash
exec >> /var/log/upload-to-s3.log 2>&1
set -e

BUCKET_NAME="${s3_bucket_name}"
LOG_FILE="/home/ubuntu/script.log"
S3_KEY="app/logs/script.log"

if [ -f "\$LOG_FILE" ]; then
  aws s3 cp "\$LOG_FILE" "s3://\$BUCKET_NAME/\$S3_KEY"
else
  echo "Log file not found: \$LOG_FILE"
fi
EOF

# Make the script executable
sudo chmod +x /usr/local/bin/upload-script-log.sh

# Create systemd shutdown service
cat <<EOF | sudo tee /etc/systemd/system/upload-script-log.service > /dev/null
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

# Auto-shutdown after 10 minutes
nohup sudo shutdown -h +10 &

exit 0

