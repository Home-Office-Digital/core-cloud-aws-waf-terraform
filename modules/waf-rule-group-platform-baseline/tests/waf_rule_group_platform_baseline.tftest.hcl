mock_provider "aws" {}

run "plan_builds_trusted_and_blocking_controls" {
  command = plan

  variables {
    name_prefix = "acme"
    environment = "dev"
    slot        = "blue"
    capacity    = 75
    tags = {
      owner = "security"
    }

    trusted_ipset_arn           = "arn:aws:wafv2:us-east-1:111122223333:regional/ipset/trusted/12345678-1234-1234-1234-123456789012"
    block_ipset_arn             = "arn:aws:wafv2:us-east-1:111122223333:regional/ipset/block/12345678-1234-1234-1234-123456789012"
    block_countries             = ["RU", "CN"]
    healthcheck_allow_ipset_arn = "arn:aws:wafv2:us-east-1:111122223333:regional/ipset/health/12345678-1234-1234-1234-123456789012"
    curl_allow_ipset_arn        = "arn:aws:wafv2:us-east-1:111122223333:regional/ipset/curl/12345678-1234-1234-1234-123456789012"

    trusted_request_rules = [
      {
        name              = "health"
        action            = "count"
        label             = "platform:trusted:path"
        methods           = ["GET"]
        uri_exact         = ["/health"]
        uri_regex         = ["^/status/[0-9]+$"]
        host_exact        = ["example.com"]
        host_regex        = ["^api\\."]
        required_headers  = ["x-request-id"]
        source_ipv4_cidrs = ["10.0.0.0/24"]
      }
    ]
  }

  assert {
    condition     = length(aws_wafv2_ip_set.trusted_request_source) == 1
    error_message = "Trusted request source CIDRs should create a supporting IP set."
  }

  assert {
    condition     = length(aws_wafv2_regex_pattern_set.trusted_request_uri_regex) == 1 && length(aws_wafv2_regex_pattern_set.trusted_request_host_regex) == 1
    error_message = "Trusted request regex inputs should create both URI and host regex pattern sets."
  }

  assert {
    condition     = aws_wafv2_rule_group.this.capacity == 75
    error_message = "Baseline rule group should honor the configured capacity."
  }

  assert {
    condition     = aws_wafv2_rule_group.this.tags["waf:policy"] == "platform" && aws_wafv2_rule_group.this.tags["waf:slot"] == "blue"
    error_message = "Baseline rule group should stamp platform/slot tags from inputs."
  }
}

run "minimal_plan_skips_optional_resources" {
  command = plan

  variables {
    name_prefix = "acme"
    environment = "dev"
    slot        = "green"
  }

  assert {
    condition     = length(aws_wafv2_ip_set.trusted_request_source) == 0 && length(aws_wafv2_regex_pattern_set.trusted_request_uri_regex) == 0 && length(aws_wafv2_regex_pattern_set.trusted_request_host_regex) == 0
    error_message = "Without trusted request inputs, no helper IP sets or regex sets should be created."
  }

  assert {
    condition     = aws_wafv2_rule_group.this.capacity == 50
    error_message = "Without an override, baseline rule group capacity should use the default value."
  }
}