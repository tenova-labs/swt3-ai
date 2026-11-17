# SWT3 Infrastructure Witness -- CloudWatch Alarms
#
# Optional alarms for the Lambda witness pipeline. Enable with:
#   enable_alarms = true
#
# Alarms notify via SNS. Provide an existing topic ARN or let the module
# create one (optionally subscribing an email address).
#
# RT-7: Alert labels reference metric names only, never fingerprints or tenant IDs.

# --- SNS Topic (optional) ---

resource "aws_sns_topic" "witness_alarms" {
  count = var.enable_alarms && var.alarm_sns_topic_arn == "" ? 1 : 0
  name  = "${var.name_prefix}-witness-alarms"
  tags  = local.common_tags
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.enable_alarms && var.alarm_sns_topic_arn == "" && var.alarm_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.witness_alarms[0].arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

locals {
  alarm_topic_arn = var.enable_alarms ? (
    var.alarm_sns_topic_arn != "" ? var.alarm_sns_topic_arn : (
      length(aws_sns_topic.witness_alarms) > 0 ? aws_sns_topic.witness_alarms[0].arn : ""
    )
  ) : ""

  alarm_actions = local.alarm_topic_arn != "" ? [local.alarm_topic_arn] : []
}

# --- Lambda Errors ---
# Fires when the witness Lambda has too many invocation errors.

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  count               = var.enable_alarms ? 1 : 0
  alarm_name          = "${var.name_prefix}-witness-lambda-errors"
  alarm_description   = "SWT3 witness Lambda invocation errors exceed threshold. Check CloudWatch logs: ${aws_cloudwatch_log_group.witness.name}"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 3
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  tags                = local.common_tags

  dimensions = {
    FunctionName = aws_lambda_function.witness.function_name
  }

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions
}

# --- DLQ Depth ---
# Fires when poison messages land in the dead letter queue.
# Any DLQ message means CloudTrail events failed processing 3 times.

resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  count               = var.enable_alarms ? 1 : 0
  alarm_name          = "${var.name_prefix}-witness-dlq-depth"
  alarm_description   = "SWT3 witness DLQ has messages. Events failed processing 3 times. Investigate: aws sqs receive-message --queue-url ${aws_sqs_queue.witness_dlq.id}"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  tags                = local.common_tags

  dimensions = {
    QueueName = aws_sqs_queue.witness_dlq.name
  }

  alarm_actions = local.alarm_actions
  ok_actions    = local.alarm_actions
}

# --- Lambda Duration ---
# Fires when Lambda execution duration approaches the timeout.
# Threshold: 80% of configured timeout.

resource "aws_cloudwatch_metric_alarm" "lambda_duration" {
  count               = var.enable_alarms ? 1 : 0
  alarm_name          = "${var.name_prefix}-witness-lambda-duration"
  alarm_description   = "SWT3 witness Lambda duration approaching timeout (${var.lambda_timeout}s). May need higher memory or timeout."
  namespace           = "AWS/Lambda"
  metric_name         = "Duration"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 2
  threshold           = var.lambda_timeout * 1000 * 0.8
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  tags                = local.common_tags

  dimensions = {
    FunctionName = aws_lambda_function.witness.function_name
  }

  alarm_actions = local.alarm_actions
}

# --- Lambda Throttles ---
# Fires when Lambda executions are throttled (concurrency limit hit).

resource "aws_cloudwatch_metric_alarm" "lambda_throttles" {
  count               = var.enable_alarms ? 1 : 0
  alarm_name          = "${var.name_prefix}-witness-lambda-throttles"
  alarm_description   = "SWT3 witness Lambda is being throttled. Current reserved concurrency: ${var.reserved_concurrent_executions}. Consider increasing."
  namespace           = "AWS/Lambda"
  metric_name         = "Throttles"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  tags                = local.common_tags

  dimensions = {
    FunctionName = aws_lambda_function.witness.function_name
  }

  alarm_actions = local.alarm_actions
}
