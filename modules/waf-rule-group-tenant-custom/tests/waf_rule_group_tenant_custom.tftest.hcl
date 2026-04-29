mock_provider "aws" {}

run "plan_builds_all_tenant_controls" {
  command = plan

  variables {
    name_prefix     = "acme"
    tenant          = "tenant-a"
    slot            = "blue"
    allow_ipset_arn = "arn:aws:wafv2:us-east-1:111122223333:regional/ipset/allow/12345678-1234-1234-1234-123456789012"
    block_ipset_arn = "arn:aws:wafv2:us-east-1:111122223333:regional/ipset/block/12345678-1234-1234-1234-123456789012"
    allow_countries = ["US"]
    block_countries = ["RU"]
    tags = {
      owner = "security"
    }
  }

  assert {
    condition     = output.rule_group_name == "acme-tenant-tenant-a-blue"
    error_message = "Tenant custom rule group should use the expected naming pattern."
  }

  assert {
    condition     = aws_wafv2_rule_group.this.tags["waf:tenant"] == "tenant-a"
    error_message = "Tenant custom rule group should carry the tenant tag."
  }

  assert {
    condition     = length(aws_wafv2_rule_group.this.rule) == 4
    error_message = "Providing tenant allow/block IPs and geo controls should emit all four tenant rules."
  }
}

run "plan_skips_optional_tenant_rules_without_inputs" {
  command = plan

  variables {
    name_prefix = "acme"
    tenant      = "tenant-a"
    slot        = "green"
  }

  assert {
    condition     = length(aws_wafv2_rule_group.this.rule) == 0
    error_message = "Without tenant IP or geo inputs, the tenant rule group should not emit optional rules."
  }
}