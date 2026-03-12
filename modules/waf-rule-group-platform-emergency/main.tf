locals {
  name = "${var.name_prefix}-platform-emergency-${var.kind}-${var.slot}"
}

resource "aws_wafv2_rule_group" "this" {
  name        = local.name
  description = "Platform emergency ${var.kind} rule group for slot ${var.slot}"
  scope       = "REGIONAL"
  capacity    = 50

  dynamic "rule" {
    for_each = var.block_ipset_arn == null ? [] : [1]
    content {
      name     = "platform-emergency-ip-block"
      priority = 1

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
        metric_name                = "platform_emergency_ip_block_${var.kind}_${var.slot}"
        sampled_requests_enabled   = true
      }
    }
  }

  dynamic "rule" {
    for_each = length(var.block_countries) == 0 ? [] : [1]
    content {
      name     = "platform-emergency-geo-block"
      priority = 2

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
        metric_name                = "platform_emergency_geo_block_${var.kind}_${var.slot}"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "platform_emergency_${var.kind}_${var.slot}"
    sampled_requests_enabled   = true
  }

  tags = merge(var.tags, {
    "waf:slot"   = var.slot
    "waf:policy" = "platform"
    "waf:type"   = "emergency-${var.kind}"
    "waf:env"    = var.environment
  })
}