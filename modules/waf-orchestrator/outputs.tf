output "default_policies" {
  description = "Default FMS policies keyed by slot."
  value = {
    for k, m in module.default_policies :
    k => {
      policy_id   = try(m.policy_id, null)
      policy_name = try(m.policy_name, null)
    }
  }
}

output "tenant_policies" {
  description = "Tenant FMS policies keyed by <tenant>-<slot>."
  value = {
    for k, m in module.tenant_policies :
    k => {
      policy_id   = try(m.policy_id, null)
      policy_name = try(m.policy_name, null)
    }
  }
}

output "tenant_rule_groups" {
  description = "Tenant custom rule groups keyed by <tenant>-<slot>."
  value = {
    for k, m in module.tenant_rule_groups :
    k => {
      rule_group_arn  = try(m.rule_group_arn, null)
      rule_group_id   = try(m.rule_group_id, null)
      rule_group_name = try(m.rule_group_name, null)
    }
  }
}

output "tenant_ip_sets" {
  description = "Tenant IP sets keyed by <tenant>-<slot>. Values are null when not created."
  value = {
    for k, v in local.tenant_slot_matrix :
    k => {
      tenant          = v.tenant
      slot            = v.slot
      allow_ipset_arn = try(aws_wafv2_ip_set.tenant_allow[k].arn, null)
      block_ipset_arn = try(aws_wafv2_ip_set.tenant_block[k].arn, null)
    }
  }
}

output "default_resource_tags_by_slot" {
  description = "Resource tags for default policy attachment. Exclude-mode (org-default) returns exclusion tags; include-mode returns the full opt-in tag set."
  value = {
    for slot in var.slots : slot => (
      try(var.slot_config[slot].policy_selector, "default_include") == "default"
      ? {
          # Path C / skip catch-all: resources with this tag are not org-default.
          "waf:coverage" = "custom"
        }
      : {
          "waf:coverage" = "custom"
          "waf:selector" = try(var.slot_config[slot].policy_selector, "default_include")
          "waf:slot"     = slot
        }
    )
  }
}

output "opt_out_resource_tags" {
  description = "Tags for explicit full WAF opt-out (Path C). Skips org-default; matches no include-mode policy."
  value = {
    "waf:coverage" = "custom"
    "waf:opt-out"  = "true"
  }
}

output "tenant_resource_tags" {
  description = "Expected resource tags per tenant-slot for FMS policy attachment."
  value = {
    for key, value in local.tenant_slot_matrix :
    key => {
      "waf:coverage" = "custom"
      "waf:selector" = "tenant"
      "waf:tenant"   = value.tenant
      "waf:slot"     = value.slot
    }
  }
}

output "effective_platform_exclude_account_ids" {
  description = "Effective list of account IDs excluded from platform default policies (platform + all tenant exclusions combined)."
  value       = local.effective_platform_exclude
}
