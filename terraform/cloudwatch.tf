# CloudWatch Log Group for script logs
resource "aws_cloudwatch_log_group" "script_logs" {
  name              = "/aws/ec2/script-logs"
  retention_in_days = 7

  tags = {
    Environment = var.stage
    Purpose     = "Script log monitoring"
  }
}

# Metric filter for ERROR and Exception keywords
resource "aws_cloudwatch_log_metric_filter" "error_exception_filter" {
  name           = "ErrorExceptionFilter-${var.stage}"
  log_group_name = aws_cloudwatch_log_group.script_logs.name
  pattern        = "[timestamp, request_id, level=ERROR || level=Exception, ...]"  # Better pattern

  metric_transformation {
    name      = "ErrorCount"
    namespace = "ScriptLogs/${var.stage}"
    value     = "1"
  }
}

# SNS Topic for error alerts
resource "aws_sns_topic" "error_alerts" {
  name         = "app-alerts-topic-${var.stage}"  # Make unique per stage
  display_name = "Script Error Alerts"
  
  tags = {
    Environment = var.stage
  }
}

# IMPORTANT: SNS Topic Policy to allow CloudWatch to publish
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
}

# CloudWatch Alarm - triggers when errors found
resource "aws_cloudwatch_metric_alarm" "script_error_alarm" {
  alarm_name          = "script-errors-${var.stage}"
  comparison_operator = "GreaterThanOrEqualToThreshold"  # Changed from GreaterThanThreshold
  evaluation_periods  = 1
  metric_name         = "ErrorCount"
  namespace           = "ScriptLogs/${var.stage}"
  period              = 60  
  statistic           = "Sum"
  threshold           = 1     # Trigger when 1 or more errors
  alarm_description   = "Alert when ERROR or Exception found in script.log"
  alarm_actions       = [aws_sns_topic.error_alerts.arn]
  ok_actions          = [aws_sns_topic.error_alerts.arn]  
  treat_missing_data  = "notBreaching"
  datapoints_to_alarm = 1     # Trigger immediately when threshold is met

  tags = {
    Environment = var.stage
    Purpose     = "Script error monitoring"
  }

  depends_on = [aws_sns_topic_policy.error_alerts_policy]
}