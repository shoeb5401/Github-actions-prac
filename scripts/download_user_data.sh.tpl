#!/bin/bash
exec > /home/ubuntu/setup.log 2>&1
set -x

sudo apt update && sudo apt upgrade -y
sudo apt install unzip -y

# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
rm -rf awscliv2.zip aws/
