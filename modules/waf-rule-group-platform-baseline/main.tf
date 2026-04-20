locals {
  name = "${var.name_prefix}-platform-baseline-${var.slot}"

  trusted_request_source_ip_sets = {
    for idx, rule in var.trusted_request_rules :
    tostring(idx) => rule.source_ipv4_cidrs
    if length(try(rule.source_ipv4_cidrs, [])) > 0
  }

  trusted_request_uri_regex_sets = {
    for idx, rule in var.trusted_request_rules :
    tostring(idx) => rule.uri_regex
    if length(try(rule.uri_regex, [])) > 0
  }

  trusted_request_host_regex_sets = {
    for idx, rule in var.trusted_request_rules :
    tostring(idx) => rule.host_regex
    if length(try(rule.host_regex, [])) > 0
  }

  # Pre-compute per-rule URI statement count so we know whether
  # to emit a single statement or wrap in or_statement.
  # uri_exact contributes one statement per entry.
  # uri_regex contributes one statement (the pattern set reference) if non-empty.
  trusted_request_uri_statement_count = {
    for idx, rule in var.trusted_request_rules :
    tostring(idx) => length(rule.uri_exact) + (length(rule.uri_regex) > 0 ? 1 : 0)
  }

  # Same for host.
  trusted_request_host_statement_count = {
    for idx, rule in var.trusted_request_rules :
    tostring(idx) => length(rule.host_exact) + (length(rule.host_regex) > 0 ? 1 : 0)
  }
}

resource "aws_wafv2_ip_set" "trusted_request_source" {
  for_each = local.trusted_request_source_ip_sets

  name               = "${local.name}-trusted-request-source-${each.key}"
  description        = "Trusted request source CIDRs for ${var.slot} rule ${each.key}"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = each.value

  tags = merge(var.tags, {
    "waf:policy" = "platform"
    "waf:slot"   = var.slot
    "waf:type"   = "trusted-request-source"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_wafv2_regex_pattern_set" "trusted_request_uri_regex" {
  for_each = local.trusted_request_uri_regex_sets

  name  = "${local.name}-trusted-request-uri-regex-${each.key}"
  scope = "REGIONAL"

  dynamic "regular_expression" {
    for_each = each.value
    content {
      regex_string = regular_expression.value
    }
  }

  tags = merge(var.tags, {
    "waf:policy" = "platform"
    "waf:slot"   = var.slot
    "waf:type"   = "trusted-request-uri-regex"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_wafv2_regex_pattern_set" "trusted_request_host_regex" {
  for_each = local.trusted_request_host_regex_sets

  name  = "${local.name}-trusted-request-host-regex-${each.key}"
  scope = "REGIONAL"

  dynamic "regular_expression" {
    for_each = each.value
    content {
      regex_string = regular_expression.value
    }
  }

  tags = merge(var.tags, {
    "waf:policy" = "platform"
    "waf:slot"   = var.slot
    "waf:type"   = "trusted-request-host-regex"
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

  depends_on = [
    aws_wafv2_ip_set.trusted_request_source,
    aws_wafv2_regex_pattern_set.trusted_request_uri_regex,
    aws_wafv2_regex_pattern_set.trusted_request_host_regex,
  ]

  ############################################################
  # Rule 0: Allow ALB Health Checks (explicit allow)
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
  # Rule 10: Platform Trusted IPs (label-only)
  ############################################################
  dynamic "rule" {
    for_each = var.trusted_ipset_arn == null ? [] : [1]

    content {
      name     = "platform-trusted-ip"
      priority = 10

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
  # Rule 20+: Generic trusted request rules
  #
  # WAFv2 constraints enforced here:
  #   - and_statement requires >= 2 child statements
  #   - or_statement requires >= 2 child statements
  #
  # Strategy:
  #   - methods: single → byte_match; multiple → or_statement
  #   - uri: 0 total → nothing; 1 total → single byte_match or
  #     regex_pattern_set_reference; >1 total → or_statement
  #     (total = len(uri_exact) + (1 if uri_regex non-empty))
  #   - host: same pattern as uri
  #   - required_headers: one statement per header (size_constraint)
  #   - source_ipv4_cidrs: one ip_set_reference if non-empty
  #
  # Because and_statement needs >= 2 children, rules must have
  # at least two of: methods, uri, host, required_headers,
  # source_ipv4_cidrs. Validation should be enforced in the
  # calling layer (Terragrunt locals) — not silently swallowed here.
  ############################################################
  dynamic "rule" {
    for_each = {
      for idx, rule in var.trusted_request_rules :
      tostring(idx) => rule
    }

    content {
      name     = "trusted-request-${rule.key}-${rule.value.name}"
      priority = 20 + tonumber(rule.key)

      dynamic "action" {
        for_each = rule.value.action == "allow" ? [1] : []
        content {
          allow {}
        }
      }

      dynamic "action" {
        for_each = rule.value.action == "count" ? [1] : []
        content {
          count {}
        }
      }

      dynamic "action" {
        for_each = rule.value.action == "block" ? [1] : []
        content {
          block {}
        }
      }

      dynamic "rule_label" {
        for_each = rule.value.action == "count" && try(rule.value.label, null) != null ? [1] : []
        content {
          name = rule.value.label
        }
      }

      statement {
        and_statement {

          ##################################################
          # Source IPv4 CIDRs — one ip_set_reference
          ##################################################
          dynamic "statement" {
            for_each = length(rule.value.source_ipv4_cidrs) > 0 ? [1] : []
            content {
              ip_set_reference_statement {
                arn = aws_wafv2_ip_set.trusted_request_source[rule.key].arn
              }
            }
          }

          ##################################################
          # Methods
          # Single method  → bare byte_match (no or_statement)
          # Multiple methods → or_statement wrapping byte_matches
          # Zero methods   → nothing (and_statement child omitted)
          ##################################################
          dynamic "statement" {
            for_each = length(rule.value.methods) == 1 ? [rule.value.methods[0]] : []
            content {
              byte_match_statement {
                search_string         = upper(statement.value)
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
          }

          dynamic "statement" {
            for_each = length(rule.value.methods) > 1 ? [1] : []
            content {
              or_statement {
                dynamic "statement" {
                  for_each = rule.value.methods
                  content {
                    byte_match_statement {
                      search_string         = upper(statement.value)
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
                }
              }
            }
          }

          ##################################################
          # URI path matching
          #
          # Total URI statement count (pre-computed in locals):
          #   = len(uri_exact) + (1 if uri_regex non-empty else 0)
          #
          # 0 total → nothing
          # 1 total → single statement (byte_match or regex_pattern_set)
          # >1 total → or_statement containing all exact byte_matches
          #             + one regex_pattern_set if uri_regex non-empty
          ##################################################

          # Exactly one uri_exact, no uri_regex → single byte_match
          dynamic "statement" {
            for_each = local.trusted_request_uri_statement_count[rule.key] == 1 && length(rule.value.uri_exact) == 1 ? [rule.value.uri_exact[0]] : []
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

          # Exactly one uri_regex, no uri_exact → single regex_pattern_set
          dynamic "statement" {
            for_each = local.trusted_request_uri_statement_count[rule.key] == 1 && length(rule.value.uri_regex) > 0 ? [1] : []
            content {
              regex_pattern_set_reference_statement {
                arn = aws_wafv2_regex_pattern_set.trusted_request_uri_regex[rule.key].arn

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

          # More than one total URI statement → or_statement
          dynamic "statement" {
            for_each = local.trusted_request_uri_statement_count[rule.key] > 1 ? [1] : []
            content {
              or_statement {
                dynamic "statement" {
                  for_each = rule.value.uri_exact
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

                dynamic "statement" {
                  for_each = length(rule.value.uri_regex) > 0 ? [1] : []
                  content {
                    regex_pattern_set_reference_statement {
                      arn = aws_wafv2_regex_pattern_set.trusted_request_uri_regex[rule.key].arn

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
          }

          ##################################################
          # Host header matching — same pattern as URI
          ##################################################

          # Exactly one host_exact, no host_regex → single byte_match
          dynamic "statement" {
            for_each = local.trusted_request_host_statement_count[rule.key] == 1 && length(rule.value.host_exact) == 1 ? [rule.value.host_exact[0]] : []
            content {
              byte_match_statement {
                search_string         = lower(statement.value)
                positional_constraint = "EXACTLY"

                field_to_match {
                  single_header {
                    name = "host"
                  }
                }

                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
              }
            }
          }

          # Exactly one host_regex, no host_exact → single regex_pattern_set
          dynamic "statement" {
            for_each = local.trusted_request_host_statement_count[rule.key] == 1 && length(rule.value.host_regex) > 0 ? [1] : []
            content {
              regex_pattern_set_reference_statement {
                arn = aws_wafv2_regex_pattern_set.trusted_request_host_regex[rule.key].arn

                field_to_match {
                  single_header {
                    name = "host"
                  }
                }

                text_transformation {
                  priority = 0
                  type     = "LOWERCASE"
                }
              }
            }
          }

          # More than one total host statement → or_statement
          dynamic "statement" {
            for_each = local.trusted_request_host_statement_count[rule.key] > 1 ? [1] : []
            content {
              or_statement {
                dynamic "statement" {
                  for_each = rule.value.host_exact
                  content {
                    byte_match_statement {
                      search_string         = lower(statement.value)
                      positional_constraint = "EXACTLY"

                      field_to_match {
                        single_header {
                          name = "host"
                        }
                      }

                      text_transformation {
                        priority = 0
                        type     = "LOWERCASE"
                      }
                    }
                  }
                }

                dynamic "statement" {
                  for_each = length(rule.value.host_regex) > 0 ? [1] : []
                  content {
                    regex_pattern_set_reference_statement {
                      arn = aws_wafv2_regex_pattern_set.trusted_request_host_regex[rule.key].arn

                      field_to_match {
                        single_header {
                          name = "host"
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
            }
          }

          ##################################################
          # Required headers — one size_constraint per header
          ##################################################
          dynamic "statement" {
            for_each = rule.value.required_headers
            content {
              size_constraint_statement {
                comparison_operator = "GT"
                size                = 0

                field_to_match {
                  single_header {
                    name = lower(statement.value)
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
        metric_name                = "trusted_request_${rule.key}"
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