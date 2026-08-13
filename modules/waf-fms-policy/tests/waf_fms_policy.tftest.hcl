mock_provider "aws" {}

run "default_policy_uses_exclude_mode_and_default_name" {
  command = plan

  variables {
    name_prefix              = "acme"
    environment              = "dev"
    slot                     = "blue"
    policy_selector          = "default"
    essential_rule_group_arn = "arn:aws:wafv2:us-east-1:111122223333:regional/rulegroup/essential/12345678-1234-1234-1234-123456789012"
  }

  assert {
    condition     = output.policy_name == "acme-platform-waf-policy-blue"
    error_message = "Default selector should produce the platform policy name."
  }

  assert {
    condition     = aws_fms_policy.this.exclude_resource_tags
    error_message = "Default selector must enable exclude_resource_tags mode."
  }

  assert {
    condition     = aws_fms_policy.this.resource_tags["waf:coverage"] == "custom"
    error_message = "Default selector should exclude resources tagged waf:coverage=custom."
  }
}

run "tenant_policy_uses_include_mode_and_tenant_name" {
  command = plan

  variables {
    name_prefix              = "acme"
    environment              = "prod"
    slot                     = "green"
    policy_selector          = "tenant"
    tenant                   = "tenant-a"
    include_account_ids      = ["111122223333"]
    essential_rule_group_arn = "arn:aws:wafv2:us-east-1:111122223333:regional/rulegroup/essential/12345678-1234-1234-1234-123456789012"
    tenant_rule_group_arn    = "arn:aws:wafv2:us-east-1:111122223333:regional/rulegroup/tenant/12345678-1234-1234-1234-123456789012"
  }

  assert {
    condition     = output.policy_name == "acme-tenant-tenant-a-waf-policy-green"
    error_message = "Tenant selector should produce the tenant policy name."
  }

  assert {
    condition     = !aws_fms_policy.this.exclude_resource_tags
    error_message = "Tenant selector must use include mode for resource tags."
  }

  assert {
    condition = (
      aws_fms_policy.this.resource_tags["waf:selector"] == "tenant" &&
      aws_fms_policy.this.resource_tags["waf:coverage"] == "custom"
    )
    error_message = "Tenant selector should inject tenant include tags including waf:coverage=custom."
  }
}

run "tenant_policy_requires_include_account_ids" {
  command = plan

  variables {
    name_prefix              = "acme"
    environment              = "prod"
    slot                     = "green"
    policy_selector          = "tenant"
    tenant                   = "tenant-a"
    essential_rule_group_arn = "arn:aws:wafv2:us-east-1:111122223333:regional/rulegroup/essential/12345678-1234-1234-1234-123456789012"
    tenant_rule_group_arn    = "arn:aws:wafv2:us-east-1:111122223333:regional/rulegroup/tenant/12345678-1234-1234-1234-123456789012"
  }

  expect_failures = [aws_fms_policy.this]
}

run "tenant_value_not_allowed_for_default_selector" {
  command = plan

  variables {
    name_prefix              = "acme"
    environment              = "dev"
    slot                     = "blue"
    policy_selector          = "default"
    tenant                   = "tenant-a"
    essential_rule_group_arn = "arn:aws:wafv2:us-east-1:111122223333:regional/rulegroup/essential/12345678-1234-1234-1234-123456789012"
  }

  expect_failures = [aws_fms_policy.this]
}

run "include_and_exclude_accounts_are_mutually_exclusive" {
  command = plan

  variables {
    name_prefix              = "acme"
    environment              = "dev"
    slot                     = "blue"
    policy_selector          = "default_include"
    include_account_ids      = ["111122223333"]
    exclude_account_ids      = ["444455556666"]
    essential_rule_group_arn = "arn:aws:wafv2:us-east-1:111122223333:regional/rulegroup/essential/12345678-1234-1234-1234-123456789012"
  }

  expect_failures = [aws_fms_policy.this]
}

run "single_resource_type_uses_resource_type_not_list" {
  command = plan

  variables {
    name_prefix              = "acme"
    environment              = "dev"
    slot                     = "alb-internal-blue"
    policy_selector          = "default_include"
    essential_rule_group_arn = "arn:aws:wafv2:us-east-1:111122223333:regional/rulegroup/essential/12345678-1234-1234-1234-123456789012"
    resource_type_list       = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
  }

  assert {
    condition     = aws_fms_policy.this.resource_type == "AWS::ElasticLoadBalancingV2::LoadBalancer"
    error_message = "A single resource type must be set via resource_type to avoid FMS perpetual drift."
  }
}

run "core_rule_set_can_run_in_count_mode" {
  command = plan

  variables {
    name_prefix                   = "acme"
    environment                   = "dev"
    slot                          = "org-default"
    policy_selector               = "default"
    essential_rule_group_arn      = "arn:aws:wafv2:us-east-1:111122223333:regional/rulegroup/essential/12345678-1234-1234-1234-123456789012"
    enable_core_rule_set          = true
    core_rule_set_override_action = "COUNT"
    enable_ip_reputation          = true
    enable_anonymous_ip           = false
    enable_bot_control            = false
    enable_layer7_ddos            = true
  }

  assert {
    condition = anytrue([
      for rg in jsondecode(aws_fms_policy.this.security_service_policy_data[0].managed_service_data).preProcessRuleGroups :
      try(rg.managedRuleGroupIdentifier.managedRuleGroupName, "") == "AWSManagedRulesCommonRuleSet" &&
      try(rg.overrideAction.type, "") == "COUNT"
    ])
    error_message = "Common Rule Set should use overrideAction COUNT when core_rule_set_override_action=COUNT."
  }
}

run "managed_only_policy_omits_essential_and_baseline" {
  command = plan

  variables {
    name_prefix                               = "acme"
    environment                               = "dev"
    slot                                      = "org-default"
    policy_selector                           = "default"
    essential_rule_group_arn                  = null
    platform_baseline_rule_group_arn          = null
    platform_emergency_first_rule_group_arn   = "arn:aws:wafv2:us-east-1:111122223333:regional/rulegroup/emergency-first/12345678-1234-1234-1234-123456789012"
    platform_emergency_last_rule_group_arn    = "arn:aws:wafv2:us-east-1:111122223333:regional/rulegroup/emergency-last/12345678-1234-1234-1234-123456789012"
    enable_core_rule_set                      = true
    core_rule_set_override_action             = "COUNT"
    enable_ip_reputation                      = true
    enable_anonymous_ip                       = false
    enable_bot_control                        = false
    enable_layer7_ddos                        = true
  }

  assert {
    condition = (
      length([
        for rg in jsondecode(aws_fms_policy.this.security_service_policy_data[0].managed_service_data).preProcessRuleGroups :
        rg if try(rg.ruleGroupType, "") == "RuleGroup"
      ]) == 1 &&
      [
        for rg in jsondecode(aws_fms_policy.this.security_service_policy_data[0].managed_service_data).preProcessRuleGroups :
        try(rg.ruleGroupArn, "") if try(rg.ruleGroupType, "") == "RuleGroup"
      ][0] == "arn:aws:wafv2:us-east-1:111122223333:regional/rulegroup/emergency-first/12345678-1234-1234-1234-123456789012"
    )
    error_message = "Managed-only PRE stack must be emergency FIRST only (no essential/baseline custom rule groups)."
  }

  assert {
    condition = anytrue([
      for rg in jsondecode(aws_fms_policy.this.security_service_policy_data[0].managed_service_data).postProcessRuleGroups :
      try(rg.ruleGroupArn, "") == "arn:aws:wafv2:us-east-1:111122223333:regional/rulegroup/emergency-last/12345678-1234-1234-1234-123456789012"
    ])
    error_message = "Managed-only policies must still attach emergency LAST in POST."
  }
}

run "default_include_requires_coverage_tag" {
  command = plan

  variables {
    name_prefix              = "acme"
    environment              = "dev"
    slot                     = "alb-external-blue"
    policy_selector          = "default_include"
    essential_rule_group_arn = "arn:aws:wafv2:us-east-1:111122223333:regional/rulegroup/essential/12345678-1234-1234-1234-123456789012"
    resource_type_list       = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
  }

  assert {
    condition = (
      aws_fms_policy.this.resource_tags["waf:coverage"] == "custom" &&
      aws_fms_policy.this.resource_tags["waf:selector"] == "default_include" &&
      aws_fms_policy.this.resource_tags["waf:slot"] == "alb-external-blue"
    )
    error_message = "Include-mode platform policies must require waf:coverage=custom plus selector/slot tags."
  }
}