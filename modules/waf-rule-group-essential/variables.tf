variable "name_prefix" {
  type = string
}

variable "environment" {
  type = string
}

variable "slot" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}

# --- toggles/limits (these match what your existing main.tf is already using)
variable "enable_global_rate" {
  type    = bool
  default = true
}

variable "global_rate_limit" {
  type    = number
  default = 2000
}

variable "enable_get_rate" {
  type    = bool
  default = true
}

variable "get_rate_limit" {
  type    = number
  default = 1000
}

variable "enable_write_rate" {
  type    = bool
  default = true
}

variable "write_rate_limit" {
  type    = number
  default = 300
}

variable "enable_body_size" {
  type    = bool
  default = true
}

variable "body_size_bytes" {
  type        = number
  default     = 8192  # 8KB — matches WAF's default body inspection limit
  description = "Maximum request body size in bytes. AWS WAF inspects up to 8KB by default. Requests exceeding this are blocked via oversizeFields handling regardless of this value."
}