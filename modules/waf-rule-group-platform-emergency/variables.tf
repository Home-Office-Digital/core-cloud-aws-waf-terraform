variable "name_prefix" {
  type = string
}

variable "slot" {
  type = string
}

# "first" or "last" (or whatever you standardize on)
variable "kind" {
  type = string
}

variable "block_ipset_arn" {
  type    = string
  default = null
}

# ISO 3166-1 alpha-2, e.g. ["RU","CN"]
variable "block_countries" {
  type    = list(string)
  default = []
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "environment" {
  description = "Environment identifier (dev/prod)."
  type        = string
}