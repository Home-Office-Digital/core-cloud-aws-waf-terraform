variable "name_prefix" {
  type = string
}

variable "environment" {
  type = string
}

variable "slot" {
  type = string
}

variable "trusted_request_rules" {
  type = list(object({
    name   = string
    action = string
    label  = optional(string)

    methods = list(string)

    uri_exact = list(string)
    uri_regex = list(string)

    host_exact = list(string)
    host_regex = list(string)

    required_headers = list(string)

    source_ipv4_cidrs = list(string)
  }))
  default = []
}

############################################################
# TRUSTED (LABEL ONLY)
############################################################
variable "trusted_ipset_arn" {
  type    = string
  default = null
}

############################################################
# BLOCKS
############################################################
variable "block_ipset_arn" {
  type    = string
  default = null
}

variable "block_countries" {
  type    = list(string)
  default = []
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "healthcheck_allow_ipset_arn" {
  type    = string
  default = null
}

variable "curl_allow_ipset_arn" {
  type    = string
  default = null
}