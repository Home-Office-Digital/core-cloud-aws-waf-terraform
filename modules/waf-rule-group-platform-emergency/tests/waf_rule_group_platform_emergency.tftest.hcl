mock_provider "aws" {}

run "plan_builds_both_emergency_rules_when_inputs_exist" {
  command = plan

  variables {
    name_prefix      = "acme"
    environment      = "prod"
    slot             = "blue"
    kind             = "first"
    block_ipset_arn  = "arn:aws:wafv2:us-east-1:111122223333:regional/ipset/block/12345678-1234-1234-1234-123456789012"
    block_countries  = ["RU", "CN"]
    tags = {
      owner = "security"
    }
  }

  assert {
    condition     = output.rule_group_name == "acme-platform-emergency-first-blue"
    error_message = "Emergency rule group name should include kind and slot."
  }

  assert {
    condition     = aws_wafv2_rule_group.this.tags["waf:type"] == "emergency-first"
    error_message = "Emergency rule group should tag its kind in waf:type."
  }

  assert {
    condition     = length(aws_wafv2_rule_group.this.rule) == 2
    error_message = "Providing both IP and geo blocks should emit both emergency rules."
  }
}

run "plan_skips_optional_rules_without_inputs" {
  command = plan

  variables {
    name_prefix = "acme"
    environment = "prod"
    slot        = "green"
    kind        = "last"
  }

  assert {
    condition     = output.rule_group_name == "acme-platform-emergency-last-green"
    error_message = "Emergency naming should stay stable without optional rules."
  }

  assert {
    condition     = length(aws_wafv2_rule_group.this.rule) == 0
    error_message = "Without emergency inputs, no emergency rules should be created."
  }
}