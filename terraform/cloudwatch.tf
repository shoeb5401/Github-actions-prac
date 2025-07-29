# CloudWatch Log Group for script logs
resource "aws_cloudwatch_log_group" "script_logs" {
  name              = "/aws/ec2/script-logs"
  retention_in_days = 7

  tags = {
    Environment = var.stage
    Purpose     = "Script log monitoring"
  }
}

# Metric filter for ERROR and Exception keywords - FIXED PATTERN
resource "aws_cloudwatch_log_metric_filter" "error_exception_filter" {
  name           = "ErrorExceptionFilter-${var.stage}"
  log_group_name = aws_cloudwatch_log_group.script_logs.name
  pattern        = "?ERROR ?Exception ?FATAL ?error ?exception"  # Simple pattern that catches errors

  metric_transformation {
    name          = "ErrorCount"
    namespace     = "ScriptLogs/${var.stage}"
    value         = "1"
    default_value = "0"  # Important: Set default value
  }
}

# SNS Topic for error alerts
resource "aws_sns_topic" "error_alerts" {
  name         = "script-error-alerts-${var.stage}"
  display_name = "Script Error Alerts - ${var.stage}"
  
  tags = {
    Environment = var.stage
    Purpose     = "Immediate error notifications"
  }
}

# CRITICAL: SNS Topic Policy to allow CloudWatch to publish
resource "aws_sns_topic_policy" "error_alerts_policy" {
  arn = aws_sns_topic.error_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action = [
          "sns:Publish"
        ]
        Resource = aws_sns_topic.error_alerts.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# Data source to get current AWS account ID
data "aws_caller_identity" "current" {}

# SNS Topic Subscription for email notifications
resource "aws_sns_topic_subscription" "email_notification" {
  topic_arn = aws_sns_topic.error_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
  
  # IMPORTANT: You MUST confirm the email subscription after terraform apply
}

# CloudWatch Alarm - IMMEDIATE ERROR DETECTION
resource "aws_cloudwatch_metric_alarm" "script_error_alarm" {
  alarm_name          = "CRITICAL-SCRIPT-ERROR-${var.stage}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1                    # Immediate trigger
  metric_name         = "ErrorCount"
  namespace           = "ScriptLogs/${var.stage}"
  period              = 60                   # Check every 1 minute
  statistic           = "Sum"
  threshold           = 1                    # ANY error triggers alert
  alarm_description   = <<-EOF
CRITICAL: Script Error Detected in ${var.stage} Environment

ERROR DETAILS:
- Environment: ${var.stage}
- Instance: ${var.stage}-writeonly-instance
- Log File: /home/ubuntu/script.log
- CloudWatch Log Group: /aws/ec2/script-logs
- S3 Backup: s3://${var.s3_bucket_name}/logs/${var.stage}/script.log

IMMEDIATE ACTION REQUIRED:
1. SSH to instance: ssh -i ${var.key_name}.pem ubuntu@[INSTANCE-IP]
2. Check logs: tail -f /home/ubuntu/script.log
3. Download S3 logs: aws s3 cp s3://${var.s3_bucket_name}/logs/${var.stage}/script.log .
4. Check application: ps aux | grep java

ALERT TRIGGERED:
This alarm activates when ERROR or Exception keywords are detected in the script logs.

Severity: CRITICAL
Contact: ${var.alert_email}

Auto-Alert from AWS CloudWatch
EOF

  alarm_actions       = [aws_sns_topic.error_alerts.arn]
  ok_actions          = [aws_sns_topic.error_alerts.arn]
  treat_missing_data  = "notBreaching"
  datapoints_to_alarm = 1

  tags = {
    Environment = var.stage
    Purpose     = "Immediate script error monitoring"
    Severity    = "Critical"
    AlertType   = "Email"
  }

  depends_on = [aws_sns_topic_policy.error_alerts_policy]
}

# Output important information
output "sns_topic_arn_for_errors" {
  description = "SNS Topic ARN for error notifications"
  value       = aws_sns_topic.error_alerts.arn
}

output "email_confirmation_warning" {
  description = "CRITICAL: Email confirmation required"
  value       = "IMPORTANT: Check email ${var.alert_email} and CONFIRM the SNS subscription to receive alerts!"
}