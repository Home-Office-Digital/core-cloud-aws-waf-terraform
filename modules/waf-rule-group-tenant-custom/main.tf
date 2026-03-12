resource "aws_wafv2_rule_group" "this" {
  name     = "${var.name_prefix}-tenant-${var.tenant}-${var.slot}"
  scope    = "REGIONAL"
  capacity = 50

  ############################################################
  # 1) Tenant Blocklist IPs (always wins inside tenant RG)
  ############################################################
  dynamic "rule" {
    for_each = var.block_ipset_arn != null ? [1] : []
    content {
      name     = "TenantBlocklist"
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
        metric_name                = "TenantBlocklist"
        sampled_requests_enabled   = true
      }
    }
  }

  ############################################################
  # 2) Tenant Geo Allow Fence
  # If allow_countries is set, everything NOT in it is blocked
  ############################################################
  dynamic "rule" {
    for_each = length(var.allow_countries) > 0 ? [1] : []
    content {
      name     = "TenantGeoAllowFence"
      priority = 2

      action {
        block {}
      }

      statement {
        not_statement {
          statement {
            geo_match_statement {
              country_codes = var.allow_countries
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "TenantGeoAllowFence"
        sampled_requests_enabled   = true
      }
    }
  }

  ############################################################
  # 3) Tenant Geo Block
  ############################################################
  dynamic "rule" {
    for_each = length(var.block_countries) > 0 ? [1] : []
    content {
      name     = "TenantGeoBlock"
      priority = 3

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
        metric_name                = "TenantGeoBlock"
        sampled_requests_enabled   = true
      }
    }
  }

  ############################################################
  # 4) Tenant Allowlist IPs
  # Runs AFTER geo → cannot bypass geo restrictions
  #
  # NOTE:
  # - This does NOT bypass Managed/Essential because tenant RG
  #   will be placed AFTER them in FMS ordering.
  ############################################################
  dynamic "rule" {
    for_each = var.allow_ipset_arn != null ? [1] : []
    content {
      name     = "TenantAllowlist"
      priority = 4

      action {
        allow {}
      }

      statement {
        ip_set_reference_statement {
          arn = var.allow_ipset_arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "TenantAllowlist"
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name_prefix}-tenant-${var.tenant}-${var.slot}"
    sampled_requests_enabled   = true
  }

  tags = merge(var.tags, {
    "waf:tenant" = var.tenant
    "waf:slot"   = var.slot
  })
}