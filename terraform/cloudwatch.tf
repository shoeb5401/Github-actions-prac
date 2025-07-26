# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "script_logs" {
  name              = "/aws/ec2/script-logs-${var.stage}"
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

# Metric Filter to detect ERROR or Exception keywords
resource "aws_cloudwatch_log_metric_filter" "error_detection" {
  name           = "ErrorDetectionFilter-${var.stage}"
  log_group_name = aws_cloudwatch_log_group.script_logs.name
  pattern        = "?ERROR ?Exception"

  metric_transformation {
    name          = "ErrorCount"
    namespace     = "CustomLogs/${var.stage}"
    value         = "1"
    default_value = "0"
  }
}

# SNS Topic for alerts
resource "aws_sns_topic" "error_alerts" {
  name = "app-alerts-topic"

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

# CloudWatch Alarm for error detection - Updated for 30-second trigger
resource "aws_cloudwatch_metric_alarm" "script_error_alarm" {
  alarm_name          = "script-errors-${var.stage}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "10"  # 10 periods of 30 seconds = 5 minutes
  metric_name         = "ErrorCount"
  namespace           = "CustomLogs/${var.stage}"
  period              = "30"  # 30 seconds instead of 60
  statistic           = "Sum"
  threshold           = "0"   # Trigger on any error (greater than 0)
  alarm_description   = "This metric monitors script.log for ERROR or Exception keywords"
  alarm_actions       = [aws_sns_topic.error_alerts.arn]
  ok_actions          = [aws_sns_topic.error_alerts.arn]
  treat_missing_data  = "notBreaching"
  datapoints_to_alarm = 2     # More than 1 datapoint as requested

  tags = {
    Environment = var.stage
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
      "arn:aws:logs:${var.region}:*:log-group:/aws/ec2/script-logs-${var.stage}",
      "arn:aws:logs:${var.region}:*:log-group:/aws/ec2/script-logs-${var.stage}:*"
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

# Attach CloudWatch policy to read-only role
resource "aws_iam_role_policy" "readonly_cloudwatch_policy" {
  name   = "CloudWatchLogsPolicy"
  role   = aws_iam_role.s3_readonly_role.id
  policy = data.aws_iam_policy_document.cloudwatch_logs_policy.json
}