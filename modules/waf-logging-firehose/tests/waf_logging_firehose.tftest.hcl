mock_provider "aws" {}

run "default_plan_builds_expected_stream_name_and_tags" {
  command = plan

  variables {
    name_prefix               = "platform"
    environment               = "dev"
    destination_s3_bucket_arn = "arn:aws:s3:::waf-log-bucket"
    s3_kms_key_arn            = "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012"
    cloudwatch_kms_key_arn    = "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012"
    tags = {
      owner = "security"
    }
  }

  assert {
    condition     = output.firehose_name == "aws-waf-logs-platform-dev"
    error_message = "Default stream name should be prefixed with aws-waf-logs-."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.this.tags["waf:component"] == "logging"
    error_message = "Firehose stream should include waf:component=logging tag."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.this.tags["waf:env"] == "dev"
    error_message = "Firehose stream should include waf:env tag from environment."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.this.tags["owner"] == "security"
    error_message = "User-provided tags should be preserved."
  }

  assert {
    condition = aws_kinesis_firehose_delivery_stream.this.extended_s3_configuration[0].prefix == "waf/!{partitionKeyFromQuery:year}/!{partitionKeyFromQuery:month}/!{partitionKeyFromQuery:day}/!{partitionKeyFromQuery:hour}/!{partitionKeyFromQuery:account_id}/!{partitionKeyFromQuery:region}/!{partitionKeyFromQuery:webacl}/"
    error_message = "Success logs should be partitioned as waf/year/month/day/hour/account/region/webacl/."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.this.extended_s3_configuration[0].error_output_prefix == "waf-errors/!{firehose:error-output-type}/"
    error_message = "Failed delivery should use waf-errors/{error-output-type}/."
  }

  assert {
    condition     = aws_cloudwatch_log_group.firehose.retention_in_days == 365
    error_message = "Firehose CloudWatch error logs must be retained for at least 1 year."
  }

  assert {
    condition = (
      aws_kinesis_firehose_delivery_stream.this.server_side_encryption[0].enabled &&
      aws_kinesis_firehose_delivery_stream.this.server_side_encryption[0].key_type == "CUSTOMER_MANAGED_CMK"
    )
    error_message = "Firehose stream must be encrypted with a customer managed CMK."
  }
}

run "custom_prefix_suffix_and_bucket_policy_acl_work" {
  command = plan

  variables {
    name_prefix               = "platform"
    environment               = "prod"
    destination_s3_bucket_arn = "arn:aws:s3:::waf-log-bucket"
    s3_kms_key_arn            = "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012"
    cloudwatch_kms_key_arn    = "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012"
    stream_name_prefix        = "aws-waf-logs-shared-"
    stream_name_suffix        = "-primary"
    manage_s3_bucket_policy   = true
    enable_put_object_acl     = true
  }

  assert {
    condition     = output.firehose_name == "aws-waf-logs-shared-platform-prod-primary"
    error_message = "If stream_name_prefix already has aws-waf-logs-, it should not be duplicated."
  }

  assert {
    condition     = length(aws_s3_bucket_policy.destination) == 1
    error_message = "S3 bucket policy resource should be created when manage_s3_bucket_policy=true."
  }

  assert {
    condition     = aws_kinesis_firehose_delivery_stream.this.destination == "extended_s3"
    error_message = "Firehose destination should be extended_s3."
  }
}

run "buffer_size_must_be_at_least_64" {
  command = plan

  variables {
    name_prefix               = "platform"
    environment               = "dev"
    destination_s3_bucket_arn = "arn:aws:s3:::waf-log-bucket"
    s3_kms_key_arn            = "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012"
    cloudwatch_kms_key_arn    = "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012"
    buffer_size_mb            = 32
  }

  expect_failures = [var.buffer_size_mb]
}

run "cloudwatch_kms_key_must_be_set" {
  command = plan

  variables {
    name_prefix               = "platform"
    environment               = "dev"
    destination_s3_bucket_arn = "arn:aws:s3:::waf-log-bucket"
    s3_kms_key_arn            = "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012"
    cloudwatch_kms_key_arn    = null
  }

  expect_failures = [var.cloudwatch_kms_key_arn]
}

run "s3_kms_key_must_be_set" {
  command = plan

  variables {
    name_prefix               = "platform"
    environment               = "dev"
    destination_s3_bucket_arn = "arn:aws:s3:::waf-log-bucket"
    s3_kms_key_arn            = null
    cloudwatch_kms_key_arn    = "arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012"
  }

  expect_failures = [var.s3_kms_key_arn]
}