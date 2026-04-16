locals {
  name = "${var.name_prefix}-platform-baseline-${var.slot}"

  # Build a map of only those rules that carry source CIDRs, keyed by rule index.
  # Used to create one ip_set per rule that needs source IP restriction.
  trusted_path_source_ip_sets = {
    for idx, rule in var.trusted_path_rules :
    tostring(idx) => rule.source_ipv4_cidrs
    if length(try(rule.source_ipv4_cidrs, [])) > 0
  }
}

############################################################
# Trusted path source IP sets (created internally so ARNs
# are always resolved within the same module, avoiding the
# (known after apply) problem that causes and_statement {})
############################################################
resource "aws_wafv2_ip_set" "trusted_path_source" {
  for_each = local.trusted_path_source_ip_sets

  name               = "${local.name}-trusted-path-source-${each.key}"
  description        = "Trusted path source CIDRs for ${var.slot} rule ${each.key}"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = each.value

  tags = merge(var.tags, {
    "waf:policy" = "platform"
    "waf:slot"   = var.slot
    "waf:type"   = "trusted-path-source"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_wafv2_rule_group" "this" {
  name        = local.name
  description = "Platform baseline rule group for slot ${var.slot}"
  scope       = "REGIONAL"
  capacity    = 50

  depends_on = [aws_wafv2_ip_set.trusted_path_source]

  ############################################################
  # Rule 0: Allow ALB Health Checks (explicit allow)
  # Allows traffic from known health check IP ranges when the
  # User-Agent matches ELB health checker. This ensures
  # load balancer health checks are never blocked by WAF.
  ############################################################
  dynamic "rule" {
    for_each = var.healthcheck_allow_ipset_arn != null ? [1] : []

    content {
      name     = "Allow-ALB-HealthChecks"
      priority = 0

      action {
        allow {}
      }

      statement {
        and_statement {
          statement {
            ip_set_reference_statement {
              arn = var.healthcheck_allow_ipset_arn
            }
          }

          statement {
            byte_match_statement {
              search_string         = "ELB-HealthChecker"
              positional_constraint = "CONTAINS"

              field_to_match {
                single_header {
                  name = "user-agent"
                }
              }

              text_transformation {
                priority = 0
                type     = "NONE"
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name}-allow-alb-healthchecks"
        sampled_requests_enabled   = true
      }
    }
  }

  ############################################################
  # Rule 1: Allow curl from Trusted IPs (explicit allow)
  # Allows curl-based requests from trusted operational IPs.
  # Used for diagnostics, scripting, and platform operations.
  # Requests must match both the IP set and User-Agent.
  ############################################################
  dynamic "rule" {
    for_each = var.curl_allow_ipset_arn != null ? [1] : []

    content {
      name     = "Allow-Curl-From-Trusted-IP"
      priority = 1

      action {
        allow {}
      }

      statement {
        and_statement {
          statement {
            ip_set_reference_statement {
              arn = var.curl_allow_ipset_arn
            }
          }

          statement {
            byte_match_statement {
              search_string         = "curl"
              positional_constraint = "CONTAINS"

              field_to_match {
                single_header {
                  name = "user-agent"
                }
              }

              text_transformation {
                priority = 0
                type     = "LOWERCASE"
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name}-allow-curl"
        sampled_requests_enabled   = true
      }
    }
  }

  ############################################################
  # Rule 2: Platform Trusted IPs (label-only)
  # Labels requests as platform:trusted for downstream rules
  # to selectively skip enforcement.
  ############################################################
  dynamic "rule" {
    for_each = var.trusted_ipset_arn == null ? [] : [1]

    content {
      name     = "platform-trusted-ip"
      priority = 2

      action {
        count {}
      }

      rule_label {
        name = "platform:trusted"
      }

      statement {
        ip_set_reference_statement {
          arn = var.trusted_ipset_arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "platform_trusted_ip"
        sampled_requests_enabled   = true
      }
    }
  }

  ############################################################
  # Rule 20+: Platform Trusted Paths (label-only) - single path
  ############################################################
  dynamic "rule" {
    for_each = {
      for idx, rule in var.trusted_path_rules :
      tostring(idx) => rule if length(try(rule.paths, [])) == 1
    }

    content {
      name     = "platform-trusted-path-${rule.key}"
      priority = 20 + tonumber(rule.key)

      action {
        count {}
      }

      rule_label {
        name = "platform:trusted:path"
      }

      statement {
        and_statement {
          statement {
            byte_match_statement {
              search_string         = upper(rule.value.method)
              positional_constraint = "EXACTLY"

              field_to_match {
                method {}
              }

              text_transformation {
                priority = 0
                type     = "NONE"
              }
            }
          }

          statement {
            byte_match_statement {
              search_string         = rule.value.paths[0]
              positional_constraint = "EXACTLY"

              field_to_match {
                uri_path {}
              }

              text_transformation {
                priority = 0
                type     = "NONE"
              }
            }
          }

          dynamic "statement" {
            for_each = length(try(rule.value.source_ipv4_cidrs, [])) > 0 ? [1] : []

            content {
              ip_set_reference_statement {
                arn = aws_wafv2_ip_set.trusted_path_source[rule.key].arn
              }
            }
          }

          dynamic "statement" {
            for_each = rule.value.require_x_hub_signature_256 ? [1] : []

            content {
              size_constraint_statement {
                comparison_operator = "GT"
                size                = 0

                field_to_match {
                  single_header {
                    name = "x-hub-signature-256"
                  }
                }

                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "platform_trusted_path_${rule.key}"
        sampled_requests_enabled   = true
      }
    }
  }

  ############################################################
  # Rule 20+: Platform Trusted Paths (label-only) - multi path
  ############################################################
  dynamic "rule" {
    for_each = {
      for idx, rule in var.trusted_path_rules :
      tostring(idx) => rule if length(try(rule.paths, [])) > 1
    }

    content {
      name     = "platform-trusted-path-${rule.key}"
      priority = 20 + tonumber(rule.key)

      action {
        count {}
      }

      rule_label {
        name = "platform:trusted:path"
      }

      statement {
        and_statement {
          statement {
            byte_match_statement {
              search_string         = upper(rule.value.method)
              positional_constraint = "EXACTLY"

              field_to_match {
                method {}
              }

              text_transformation {
                priority = 0
                type     = "NONE"
              }
            }
          }

          statement {
            or_statement {
              dynamic "statement" {
                for_each = rule.value.paths

                content {
                  byte_match_statement {
                    search_string         = statement.value
                    positional_constraint = "EXACTLY"

                    field_to_match {
                      uri_path {}
                    }

                    text_transformation {
                      priority = 0
                      type     = "NONE"
                    }
                  }
                }
              }
            }
          }

          dynamic "statement" {
            for_each = length(try(rule.value.source_ipv4_cidrs, [])) > 0 ? [1] : []

            content {
              ip_set_reference_statement {
                arn = aws_wafv2_ip_set.trusted_path_source[rule.key].arn
              }
            }
          }

          dynamic "statement" {
            for_each = rule.value.require_x_hub_signature_256 ? [1] : []

            content {
              size_constraint_statement {
                comparison_operator = "GT"
                size                = 0

                field_to_match {
                  single_header {
                    name = "x-hub-signature-256"
                  }
                }

                text_transformation {
                  priority = 0
                  type     = "NONE"
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "platform_trusted_path_${rule.key}"
        sampled_requests_enabled   = true
      }
    }
  }

  ############################################################
  # Rule 100: Platform IP Blocklist (optional)
  ############################################################
  dynamic "rule" {
    for_each = var.block_ipset_arn == null ? [] : [1]

    content {
      name     = "platform-ip-block"
      priority = 100

      action {
        block {}
      }

      statement {
        ip_set_reference_statement {
          arn = var.block_ipset_arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "platform_ip_block"
        sampled_requests_enabled   = true
      }
    }
  }

  ############################################################
  # Rule 110: Platform Geo Block (optional)
  ############################################################
  dynamic "rule" {
    for_each = length(var.block_countries) == 0 ? [] : [1]

    content {
      name     = "platform-geo-block"
      priority = 110

      action {
        block {}
      }

      statement {
        geo_match_statement {
          country_codes = var.block_countries
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "platform_geo_block"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = local.name
    sampled_requests_enabled   = true
  }

  tags = merge(var.tags, {
    "waf:policy" = "platform"
    "waf:slot"   = var.slot
    "waf:type"   = "baseline"
    "waf:env"    = var.environment
  })
}
