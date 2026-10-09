variable "name_prefix" {
  type = string
}

variable "environment" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "destination_s3_bucket_arn" {
  type = string
}

variable "s3_error_output_prefix" {
  type    = string
  default = "waf-errors"
}

variable "stream_name_prefix" {
  type    = string
  default = ""
}

variable "stream_name_suffix" {
  type    = string
  default = ""
}

variable "buffer_size_mb" {
  type    = number
  default = 64

  validation {
    condition     = var.buffer_size_mb >= 64
    error_message = "buffer_size_mb must be at least 64 when Dynamic Partitioning is enabled in Firehose."
  }
}

variable "buffer_interval_seconds" {
  type    = number
  default = 60
}

variable "compression_format" {
  type    = string
  default = "GZIP"
}

variable "s3_kms_key_arn" {
  description = "CMK ARN for S3 object encryption and Firehose stream encryption."
  type        = string

  validation {
    condition     = var.s3_kms_key_arn != null
    error_message = "s3_kms_key_arn must be set — Firehose and S3 logs must use a CMK."
  }
}

variable "firehose_error_log_retention_days" {
  type    = number
  default = 365

  validation {
    condition     = var.firehose_error_log_retention_days >= 365
    error_message = "firehose_error_log_retention_days must be at least 365."
  }
}

variable "enable_put_object_acl" {
  type    = bool
  default = false
}

variable "manage_s3_bucket_policy" {
  type    = bool
  default = false
}

variable "cloudwatch_kms_key_arn" {
  description = "KMS key ARN for CloudWatch log group encryption."
  type        = string

  validation {
    condition     = var.cloudwatch_kms_key_arn != null
    error_message = "cloudwatch_kms_key_arn must be set — CloudWatch log groups must use a CMK."
  }
}