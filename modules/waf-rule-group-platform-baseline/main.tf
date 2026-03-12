locals {
  name = "${var.name_prefix}-platform-baseline-${var.slot}"
}

resource "aws_wafv2_rule_group" "this" {
  name        = local.name
  description = "Platform baseline rule group for slot ${var.slot}"
  scope       = "REGIONAL"
  capacity    = 50

  ############################################################
  # Rule 1: Platform Trusted IPs (optional) - LABEL ONLY
  # Labels requests as platform:trusted for Essential to skip.
  # Does NOT allow/block.
  ############################################################
  dynamic "rule" {
    for_each = var.trusted_ipset_arn == null ? [] : [1]
    content {
      name     = "platform-trusted-ip"
      priority = 1

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
  # Rule 10: Platform IP Blocklist (optional)
  ############################################################
  dynamic "rule" {
    for_each = var.block_ipset_arn == null ? [] : [1]
    content {
      name     = "platform-ip-block"
      priority = 10

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
  # Rule 11: Platform Geo Block (optional)
  ############################################################
  dynamic "rule" {
    for_each = length(var.block_countries) == 0 ? [] : [1]
    content {
      name     = "platform-geo-block"
      priority = 11

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