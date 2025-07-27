# CloudWatch Log Group - FIXED to match your agent config
resource "aws_cloudwatch_log_group" "script_logs" {
  name              = "/aws/ec2/${var.stage}/script-logs"
  retention_in_days = 7

  tags = {
    Environment = var.stage
    Purpose     = "Script log monitoring"
  }
}

# CloudWatch Log Stream for writeonly instance
resource "aws_cloudwatch_log_stream" "writeonly_script_log" {
  name           = "writeonly-instance-${aws_instance.writeonly_instance.id}"
  log_group_name = aws_cloudwatch_log_group.script_logs.name
}

# CloudWatch Log Stream for readonly instance
resource "aws_cloudwatch_log_stream" "readonly_script_log" {
  name           = "readonly-instance-${aws_instance.readonly_instance.id}"
  log_group_name = aws_cloudwatch_log_group.script_logs.name
}

# FIXED: Metric filter for ERROR pattern - using correct log group reference
resource "aws_cloudwatch_log_metric_filter" "error_filter" {
  name           = "ErrorFilter-${var.stage}"
  log_group_name = aws_cloudwatch_log_group.script_logs.name  # Fixed: was referencing non-existent log group
  pattern        = "ERROR"

  metric_transformation {
    name      = "ErrorCount"
    namespace = "CustomLogs/${var.stage}"  # Fixed: consistent namespace
    value     = "1"
  }
}

# FIXED: Metric filter for Exception pattern - using correct log group reference
resource "aws_cloudwatch_log_metric_filter" "exception_filter" {
  name           = "ExceptionFilter-${var.stage}"
  log_group_name = aws_cloudwatch_log_group.script_logs.name  # Fixed: was referencing non-existent log group
  pattern        = "Exception"

  metric_transformation {
    name      = "ExceptionCount"
    namespace = "CustomLogs/${var.stage}"  # Fixed: consistent namespace
    value     = "1"
  }
}

# FIXED: Combined metric filter for both ERROR and Exception patterns
resource "aws_cloudwatch_log_metric_filter" "error_exception_filter" {
  name           = "ErrorExceptionFilter-${var.stage}"
  log_group_name = aws_cloudwatch_log_group.script_logs.name
  pattern        = "[timestamp, request_id, level=\"ERROR\" || level=\"Exception\", ...]"  # More flexible pattern

  metric_transformation {
    name      = "ErrorExceptionCount"
    namespace = "CustomLogs/${var.stage}"
    value     = "1"
  }
}

# SNS Topic for alerts
resource "aws_sns_topic" "error_alerts" {
  name         = "app-alerts-topic"
  display_name = "App Alerts – ${var.stage}"
  tags = {
    Environment = var.stage
  }
}

# SNS Topic Subscription
resource "aws_sns_topic_subscription" "email_notification" {
  topic_arn = aws_sns_topic.error_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# OPTIMIZED: CloudWatch Alarm for 30-second error detection
resource "aws_cloudwatch_metric_alarm" "script_error_alarm" {
  alarm_name          = "script-errors-${var.stage}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2     # 2 periods of 30 seconds = 1 minute total evaluation
  metric_name         = "ErrorExceptionCount"  # Using combined metric
  namespace           = "CustomLogs/${var.stage}"
  period              = 30    # 30-second periods
  statistic           = "Sum"
  threshold           = 0     # Trigger on any error (greater than 0)
  alarm_description   = "This metric monitors script.log for ERROR or Exception keywords - triggers within 30 seconds"
  alarm_actions       = [aws_sns_topic.error_alerts.arn]
  ok_actions          = [aws_sns_topic.error_alerts.arn]
  treat_missing_data  = "notBreaching"
  datapoints_to_alarm = 1     # Trigger on first occurrence for faster response

  tags = {
    Environment = var.stage
    Purpose     = "Fast error detection"
  }
}

# ADDITIONAL: Separate alarms for ERROR and Exception if you want granular monitoring
resource "aws_cloudwatch_metric_alarm" "error_only_alarm" {
  alarm_name          = "script-errors-only-${var.stage}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1     # Single evaluation period for immediate trigger
  metric_name         = "ErrorCount"
  namespace           = "CustomLogs/${var.stage}"
  period              = 30    # 30-second periods
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Immediate alert for ERROR in script.log"
  alarm_actions       = [aws_sns_topic.error_alerts.arn]
  treat_missing_data  = "notBreaching"
  datapoints_to_alarm = 1

  tags = {
    Environment = var.stage
    Type        = "ERROR-only"
  }
}

resource "aws_cloudwatch_metric_alarm" "exception_only_alarm" {
  alarm_name          = "script-exceptions-only-${var.stage}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1     # Single evaluation period for immediate trigger
  metric_name         = "ExceptionCount"
  namespace           = "CustomLogs/${var.stage}"
  period              = 30    # 30-second periods
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Immediate alert for Exception in script.log"
  alarm_actions       = [aws_sns_topic.error_alerts.arn]
  treat_missing_data  = "notBreaching"
  datapoints_to_alarm = 1

  tags = {
    Environment = var.stage
    Type        = "Exception-only"
  }
}

# CloudWatch Logs policy for both instances
data "aws_iam_policy_document" "cloudwatch_logs_policy" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
      "logs:DescribeLogGroups"
    ]
    resources = [
      "arn:aws:logs:${var.region}:*:log-group:/aws/ec2/${var.stage}/script-logs",
      "arn:aws:logs:${var.region}:*:log-group:/aws/ec2/${var.stage}/script-logs:*"
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:DescribeVolumes",
      "ec2:DescribeTags",
      "logs:PutLogEvents",
      "logs:CreateLogGroup",
      "logs:CreateLogStream"
    ]
    resources = ["*"]
  }
}

# Attach CloudWatch policy to write-only role
resource "aws_iam_role_policy" "writeonly_cloudwatch_policy" {
  name   = "CloudWatchLogsPolicy"
  role   = aws_iam_role.s3_writeonly_role.id
  policy = data.aws_iam_policy_document.cloudwatch_logs_policy.json
}

# ADDED: Attach CloudWatch policy to read-only role as well
resource "aws_iam_role_policy" "readonly_cloudwatch_policy" {
  name   = "CloudWatchLogsPolicy"
  role   = aws_iam_role.s3_readonly_role.id
  policy = data.aws_iam_policy_document.cloudwatch_logs_policy.json
}

# Attach CloudWatch Agent policy to write-only role
resource "aws_iam_role_policy_attachment" "writeonly_cw_agent" {
  role       = aws_iam_role.s3_writeonly_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# ADDED: Attach CloudWatch Agent policy to read-only role as well
resource "aws_iam_role_policy_attachment" "readonly_cw_agent" {
  role       = aws_iam_role.s3_readonly_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}