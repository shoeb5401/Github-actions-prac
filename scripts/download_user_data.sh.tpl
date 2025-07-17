#!/bin/bash


exec > /home/ubuntu/setup.log 2>&1
set -x

sudo apt update && sudo apt upgrade -y
sudo apt install unzip curl -y

# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
rm -rf awscliv2.zip aws/

sleep 150

s3_bucket_name="${s3_bucket_name}"
stage="${stage}"

if [ -z "$stage" ] || [ -z "$s3_bucket_name" ]; then
  echo "❌ stage or s3_bucket_name is empty (stage='$stage', s3_bucket_name='$s3_bucket_name')" >&2
  exit 1
fi

aws s3 cp "s3://${s3_bucket_name}/logs/${stage}/script.log" /home/ubuntu/read-script.log
