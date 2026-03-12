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
  default = "waf-logs-errors"
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
  type    = string
  default = null
}

variable "firehose_error_log_retention_days" {
  type    = number
  default = 30
}

variable "enable_put_object_acl" {
  type    = bool
  default = false
}

variable "manage_s3_bucket_policy" {
  type    = bool
  default = false
}