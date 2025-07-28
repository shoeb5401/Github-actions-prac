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
  pattern        = "ERROR Exception"  # Simple OR pattern

  metric_transformation {
    name      = "ErrorCount"
    namespace = "ScriptLogs/${var.stage}"
    value     = "1"
  }
}

# SNS Topic for error alerts
resource "aws_sns_topic" "error_alerts" {
  name         = "app-alerts-topic"
  display_name = "Script Error Alerts"
  
  tags = {
    Environment = var.stage
  }
}

# SNS Topic Subscription for email notifications  
resource "aws_sns_topic_subscription" "email_notification" {
  topic_arn = aws_sns_topic.error_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email  # Use a different email temporarily
}

# CloudWatch Alarm - triggers when more than 1 error found
resource "aws_cloudwatch_metric_alarm" "script_error_alarm" {
  alarm_name          = "script-errors-${var.stage}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ErrorCount"
  namespace           = "ScriptLogs/${var.stage}"
  period              = 60    # Check every 60 seconds
  statistic           = "Sum"
  threshold           = 1     # Trigger when more than 1 error
  alarm_description   = "Alert when more than 1 ERROR or Exception found in script.log"
  alarm_actions       = [aws_sns_topic.error_alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = {
    Environment = var.stage
    Purpose     = "Script error monitoring"
  }
}