variable "name_prefix" { type = string }
variable "tenant"      { type = string }
variable "slot"        { type = string }

variable "allow_ipset_arn" {
  type    = string
  default = null
}

variable "block_ipset_arn" {
  type    = string
  default = null
}

# Geo support
variable "allow_countries" {
  type    = list(string)
  default = []
}

variable "block_countries" {
  type    = list(string)
  default = []
}

variable "tags" {
  type    = map(string)
  default = {}
}

