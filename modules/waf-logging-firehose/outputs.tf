output "firehose_arn" {
  description = "Shared Firehose delivery stream ARN"
  value       = aws_kinesis_firehose_delivery_stream.this.arn
}

output "firehose_name" {
  description = "Shared Firehose delivery stream name"
  value       = aws_kinesis_firehose_delivery_stream.this.name
}