locals {
  name = "${var.name_prefix}-platform-essential-${var.slot}"
}

resource "aws_wafv2_rule_group" "this" {
  name     = local.name
  scope    = "REGIONAL"
  capacity = 400

  tags = merge(var.tags, {
    "waf:kind" = "essential"
    "waf:slot" = var.slot
    "waf:env"  = var.environment
  })

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = local.name
    sampled_requests_enabled   = true
  }

  ############################################################
  # Global Rate - skip trusted source IPs
  ############################################################
  dynamic "rule" {
    for_each = var.enable_global_rate ? [1] : []

    content {
      name     = "rate-global"
      priority = 10

      action {
        block {}
      }

      statement {
        rate_based_statement {
          aggregate_key_type = "IP"
          limit              = var.global_rate_limit

          scope_down_statement {
            not_statement {
              statement {
                label_match_statement {
                  scope = "LABEL"
                  key   = "platform:trusted"
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "rate-global"
        sampled_requests_enabled   = true
      }
    }
  }

  ############################################################
  # GET Rate - skip trusted source IPs
  ############################################################
  dynamic "rule" {
    for_each = var.enable_get_rate ? [1] : []

    content {
      name     = "rate-get"
      priority = 20

      action {
        block {}
      }

      statement {
        rate_based_statement {
          aggregate_key_type = "IP"
          limit              = var.get_rate_limit

          scope_down_statement {
            and_statement {
              statement {
                byte_match_statement {
                  field_to_match {
                    method {}
                  }
                  positional_constraint = "EXACTLY"
                  search_string         = "GET"

                  text_transformation {
                    priority = 0
                    type     = "NONE"
                  }
                }
              }

              statement {
                not_statement {
                  statement {
                    label_match_statement {
                      scope = "LABEL"
                      key   = "platform:trusted"
                    }
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "rate-get"
        sampled_requests_enabled   = true
      }
    }
  }

  ############################################################
  # WRITE Rate - skip trusted source IPs and trusted paths
  ############################################################
  dynamic "rule" {
    for_each = var.enable_write_rate ? [1] : []

    content {
      name     = "rate-write"
      priority = 30

      action {
        block {}
      }

      statement {
        rate_based_statement {
          aggregate_key_type = "IP"
          limit              = var.write_rate_limit

          scope_down_statement {
            and_statement {
              statement {
                or_statement {
                  statement {
                    byte_match_statement {
                      field_to_match {
                        method {}
                      }
                      positional_constraint = "EXACTLY"
                      search_string         = "POST"

                      text_transformation {
                        priority = 0
                        type     = "NONE"
                      }
                    }
                  }

                  statement {
                    byte_match_statement {
                      field_to_match {
                        method {}
                      }
                      positional_constraint = "EXACTLY"
                      search_string         = "PUT"

                      text_transformation {
                        priority = 0
                        type     = "NONE"
                      }
                    }
                  }

                  statement {
                    byte_match_statement {
                      field_to_match {
                        method {}
                      }
                      positional_constraint = "EXACTLY"
                      search_string         = "DELETE"

                      text_transformation {
                        priority = 0
                        type     = "NONE"
                      }
                    }
                  }
                }
              }

              statement {
                not_statement {
                  statement {
                    label_match_statement {
                      scope = "LABEL"
                      key   = "platform:trusted"
                    }
                  }
                }
              }

              statement {
                not_statement {
                  statement {
                    label_match_statement {
                      scope = "LABEL"
                      key   = "platform:trusted:path"
                    }
                  }
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "rate-write"
        sampled_requests_enabled   = true
      }
    }
  }

  ############################################################
  # Body size - skip trusted source IPs and trusted paths
  ############################################################
  dynamic "rule" {
    for_each = var.enable_body_size ? [1] : []

    content {
      name     = "body-size"
      priority = 40

      action {
        block {}
      }

      statement {
        and_statement {
          statement {
            size_constraint_statement {
              comparison_operator = "GT"
              size                = var.body_size_bytes

              field_to_match {
                body {
                  oversize_handling = "MATCH"
                }
              }

              text_transformation {
                priority = 0
                type     = "NONE"
              }
            }
          }

          statement {
            not_statement {
              statement {
                label_match_statement {
                  scope = "LABEL"
                  key   = "platform:trusted"
                }
              }
            }
          }

          statement {
            not_statement {
              statement {
                label_match_statement {
                  scope = "LABEL"
                  key   = "platform:trusted:path"
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "body-size"
        sampled_requests_enabled   = true
      }
    }
  }
}