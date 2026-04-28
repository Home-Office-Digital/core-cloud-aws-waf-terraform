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
    condition     = aws_fms_policy.this.resource_tags["fms-managed"] == "true"
    error_message = "Default selector should use fms-managed=true as exclusion tags."
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
    condition     = aws_fms_policy.this.resource_tags["waf:selector"] == "tenant"
    error_message = "Tenant selector should inject tenant include tags."
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

run "intentional_failure_for_ci_validation" {
  command = plan

  variables {
    name_prefix              = "acme"
    environment              = "dev"
    slot                     = "blue"
    policy_selector          = "default"
    essential_rule_group_arn = "arn:aws:wafv2:us-east-1:111122223333:regional/rulegroup/essential/12345678-1234-1234-1234-123456789012"
  }

  assert {
    condition     = output.policy_name == "this-will-always-fail"
    error_message = "Intentional failure to validate CI merge gating on failed terraform tests."
  }
}