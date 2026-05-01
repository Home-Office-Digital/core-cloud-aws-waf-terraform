mock_provider "aws" {}

run "default_plan_builds_all_essential_rules" {
  command = plan

  variables {
    name_prefix = "acme"
    environment = "dev"
    slot        = "blue"
    tags = {
      owner = "security"
    }
    trusted_path_label_key = "awswaf:111122223333:label:platform:trusted:path"
  }

  assert {
    condition     = output.rule_group_name == "acme-platform-essential-blue"
    error_message = "Essential rule group name should include the prefix and slot."
  }

  assert {
    condition     = aws_wafv2_rule_group.this.tags["waf:kind"] == "essential"
    error_message = "Essential rule group should be tagged with waf:kind=essential."
  }

  assert {
    condition     = length(aws_wafv2_rule_group.this.rule) == 4
    error_message = "Default essential configuration should emit all four protective rules."
  }
}

run "disabled_toggles_remove_optional_rules" {
  command = plan

  variables {
    name_prefix         = "acme"
    environment         = "dev"
    slot                = "green"
    enable_global_rate  = false
    enable_get_rate     = false
    enable_write_rate   = false
    enable_body_size    = false
  }

  assert {
    condition     = output.rule_group_name == "acme-platform-essential-green"
    error_message = "Rule group naming should stay stable when rules are disabled."
  }

  assert {
    condition     = length(aws_wafv2_rule_group.this.rule) == 0
    error_message = "Disabling every essential toggle should remove all optional rules."
  }
}