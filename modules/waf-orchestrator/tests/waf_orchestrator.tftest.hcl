mock_provider "aws" {
  mock_resource "aws_wafv2_ip_set" {
    defaults = {
      arn = "arn:aws:wafv2:eu-west-2:111122223333:regional/ipset/mock/11111111-1111-1111-1111-111111111111"
      id  = "11111111-1111-1111-1111-111111111111"
    }
  }

  mock_resource "aws_wafv2_rule_group" {
    defaults = {
      arn = "arn:aws:wafv2:eu-west-2:111122223333:regional/rulegroup/mock/22222222-2222-2222-2222-222222222222"
      id  = "22222222-2222-2222-2222-222222222222"
    }
  }
}

run "plan_builds_default_and_tenant_outputs" {
  command = plan

  variables {
    name_prefix    = "acme"
    environment    = "dev"
    aws_account_id = "111122223333"
    slots          = ["blue"]
    tags = {
      owner = "security"
    }

    platform_exclude_account_ids = ["999900001111"]

    platform = {
      baseline = {
        trusted_ip_sets = {
          global = {
            allowlist = ["10.0.0.0/24"]
          }
        }
        block_ip_sets = {
          global = {
            blocklist = ["192.0.2.0/24"]
          }
        }
        block_countries = {
          global = ["RU"]
        }
        trusted_request_rules = {
          global = [
            {
              name   = "health"
              action = "count"
              label  = "platform:trusted:path"
              match = {
                methods = ["GET"]
                uri = {
                  exact = ["/health"]
                  regex = []
                }
                headers = {
                  host = {
                    exact = ["example.com"]
                    regex = []
                  }
                  required = []
                }
                source = {
                  ipv4_cidrs = []
                }
              }
            }
          ]
        }
        bot_control_rules = {
          global = {
            category_http_library = "BLOCK"
          }
        }
        operational_allow = {
          healthcheck_ip_sets = {
            global = {
              allowlist = ["10.10.0.0/24"]
            }
          }
          curl_ip_sets = {
            global = {
              allowlist = ["10.20.0.0/24"]
            }
          }
        }
      }
      emergency = {
        block_ip_sets = {
          global = {
            blocklist = ["198.51.100.0/24"]
          }
        }
        block_countries = {
          global = ["CN"]
        }
      }
    }

    tenants = {
      tenant_a = {
        enabled             = true
        enable_bot_control  = true
        tags                = { team = "tenant-a" }
        include_account_ids = ["111122223333"]
        exclude_account_ids = ["222233334444"]
        ip_sets = {
          blue = {
            allowlist = ["203.0.113.1/32"]
            blocklist = ["203.0.113.2/32"]
          }
        }
        geo = {
          blue = {
            allow = ["US"]
            block = ["RU"]
          }
        }
      }
    }
  }

  assert {
    condition     = output.default_policies["blue"].policy_name == "acme-platform-waf-policy-blue"
    error_message = "Default policy output should be keyed by slot and use the platform policy name."
  }

  assert {
    condition     = output.tenant_policies["tenant_a-blue"].policy_name == "acme-tenant-tenant_a-waf-policy-blue"
    error_message = "Tenant policy output should be keyed by tenant-slot and use the tenant policy naming pattern."
  }

  assert {
    condition     = output.tenant_rule_groups["tenant_a-blue"].rule_group_name == "acme-tenant-tenant_a-blue"
    error_message = "Tenant rule group output should expose the generated tenant rule group name."
  }

  assert {
    condition     = length(aws_wafv2_ip_set.tenant_allow) == 1 && length(aws_wafv2_ip_set.tenant_block) == 1
    error_message = "Tenant allowlist and blocklist IP set resources should be created when configured."
  }

  assert {
    condition = (
      output.default_resource_tags_by_slot["blue"]["waf:coverage"] == "custom" &&
      output.default_resource_tags_by_slot["blue"]["waf:selector"] == "default_include"
    )
    error_message = "Default include tags should require waf:coverage=custom and the default_include selector."
  }

  assert {
    condition = (
      output.tenant_resource_tags["tenant_a-blue"]["waf:tenant"] == "tenant_a" &&
      output.tenant_resource_tags["tenant_a-blue"]["waf:coverage"] == "custom"
    )
    error_message = "Tenant resource tags should include coverage=custom and the tenant identifier."
  }

  assert {
    condition = (
      output.opt_out_resource_tags["waf:coverage"] == "custom" &&
      output.opt_out_resource_tags["waf:opt-out"] == "true"
    )
    error_message = "Opt-out tags should be waf:coverage=custom and waf:opt-out=true."
  }

  assert {
    condition     = length(output.effective_platform_exclude_account_ids) == 3
    error_message = "Effective platform exclusions should combine platform, tenant exclusions, and tenant include accounts."
  }
}

run "active_tenants_with_include_accounts_are_allowed" {
  command = plan

  variables {
    name_prefix    = "acme"
    environment    = "dev"
    aws_account_id = "111122223333"
    slots          = ["blue"]

    tenants = {
      tenant_a = {
        enabled             = true
        enable_bot_control  = false
        tags                = {}
        include_account_ids = ["111122223333"]
        ip_sets = {
          blue = {
            allowlist = ["203.0.113.10/32"]
            blocklist = []
          }
        }
        geo = {}
      }
    }
  }

  assert {
    condition     = length(terraform_data.tenant_account_validation) == 0
    error_message = "Tenants that define include_account_ids should not trigger tenant account validation errors."
  }

  assert {
    condition     = output.tenant_policies["tenant_a-blue"].policy_name == "acme-tenant-tenant_a-waf-policy-blue"
    error_message = "Tenant policy should be planned when include_account_ids are provided."
  }
}

run "exclude_mode_org_default_exposes_coverage_exclusion_tag" {
  command = plan

  variables {
    name_prefix    = "acme"
    environment    = "dev"
    aws_account_id = "111122223333"
    slots          = ["org-default"]

    slot_config = {
      org-default = {
        policy_selector = "default"
        resource_type_list = [
          "AWS::ElasticLoadBalancingV2::LoadBalancer",
          "AWS::ApiGateway::Stage",
        ]
        enable_platform_baseline      = false
        enable_essential              = false
        enable_core_rule_set          = true
        core_rule_set_override_action = "COUNT"
        enable_ip_reputation          = true
        enable_layer7_ddos            = true
        enable_anonymous_ip           = false
        enable_bot_control            = false
      }
    }

    platform = {
      baseline = {
        core_rule_set_rules = {
          global = {
            SizeRestrictions_BODY = "COUNT"
          }
        }
      }
      emergency = {}
    }

    tenants = {}
  }

  assert {
    condition     = output.default_policies["org-default"].policy_name == "acme-platform-waf-policy-org-default"
    error_message = "Catch-all slot should create a platform default policy."
  }

  assert {
    condition = (
      length(output.default_resource_tags_by_slot["org-default"]) == 1 &&
      output.default_resource_tags_by_slot["org-default"]["waf:coverage"] == "custom" &&
      !contains(keys(output.default_resource_tags_by_slot["org-default"]), "waf:selector")
    )
    error_message = "Exclude-mode slots should expose only the waf:coverage=custom exclusion tag."
  }

  assert {
    condition     = length(keys(module.essential_rule_groups)) == 0
    error_message = "org-default with enable_essential=false must not create an essential rule group."
  }

  assert {
    condition     = length(keys(module.platform_baseline)) == 0
    error_message = "org-default with enable_platform_baseline=false must not create a baseline rule group."
  }

  assert {
    condition = (
      length(keys(module.platform_emergency_first)) == 1 &&
      length(keys(module.platform_emergency_last)) == 1
    )
    error_message = "org-default must still create emergency first/last rule groups."
  }

  assert {
    condition     = length(output.default_policies["org-default"].include_account_ids) == 0
    error_message = "org-default without slot include_account_ids should remain org-wide exclude-mode."
  }
}

run "default_policy_include_account_ids_scopes_slot_and_clears_exclude" {
  command = plan

  variables {
    name_prefix                  = "acme"
    environment                  = "prod"
    aws_account_id               = "111122223333"
    slots                        = ["org-default", "alb-external-blue"]
    platform_exclude_account_ids = ["999999999999"]
    platform_exclude_orgunit_ids = ["ou-82pp-yuxw4n8j"]

    slot_config = {
      org-default = {
        policy_selector          = "default"
        include_account_ids      = ["034034141086"]
        enable_platform_baseline = false
        enable_essential         = false
        enable_anonymous_ip      = false
        enable_bot_control       = false
      }
      alb-external-blue = {
        policy_selector          = "default_include"
        include_account_ids      = []
        enable_platform_baseline = true
        enable_essential         = true
        enable_anonymous_ip      = true
        enable_bot_control       = true
      }
    }

    platform = {
      emergency = {}
      baseline  = {}
    }

    tenants = {}
  }

  assert {
    condition = (
      length(output.default_policies["org-default"].include_account_ids) == 1 &&
      contains(output.default_policies["org-default"].include_account_ids, "034034141086") &&
      length(output.default_policies["org-default"].exclude_account_ids) == 0
    )
    error_message = "A default slot with include_account_ids must use include_map only."
  }

  assert {
    condition     = length(output.default_policies["org-default"].exclude_orgunit_ids) == 0
    error_message = "include_map slots must omit exclude_orgunit_ids because FMS include and exclude maps are mutually exclusive."
  }

  assert {
    condition = (
      length(output.default_policies["alb-external-blue"].include_account_ids) == 0 &&
      contains(output.default_policies["alb-external-blue"].exclude_account_ids, "999999999999") &&
      contains(output.default_policies["alb-external-blue"].exclude_orgunit_ids, "ou-82pp-yuxw4n8j")
    )
    error_message = "Slots without include_account_ids should keep platform exclude_map including excluded OUs."
  }
}

run "default_policy_exclude_orgunit_ids_on_org_wide_slot" {
  command = plan

  variables {
    name_prefix                  = "acme"
    environment                  = "dev"
    aws_account_id               = "111122223333"
    slots                        = ["org-default"]
    platform_exclude_orgunit_ids = ["ou-82pp-yuxw4n8j"]

    slot_config = {
      org-default = {
        policy_selector          = "default"
        enable_platform_baseline = false
        enable_essential         = false
        enable_anonymous_ip      = false
        enable_bot_control       = false
      }
    }

    platform = {
      emergency = {}
      baseline  = {}
    }

    tenants = {}
  }

  assert {
    condition = (
      length(output.default_policies["org-default"].include_account_ids) == 0 &&
      length(output.default_policies["org-default"].exclude_orgunit_ids) == 1 &&
      contains(output.default_policies["org-default"].exclude_orgunit_ids, "ou-82pp-yuxw4n8j")
    )
    error_message = "Org-wide default slots should pass exclude_orgunit_ids into exclude_map."
  }
}

run "default_policy_include_orgunit_ids_uses_include_map" {
  command = plan

  variables {
    name_prefix                  = "acme"
    environment                  = "prod"
    aws_account_id               = "111122223333"
    slots                        = ["org-default", "alb-external-blue"]
    platform_include_orgunit_ids = ["ou-82pp-include"]
    platform_exclude_account_ids = ["999999999999"]
    platform_exclude_orgunit_ids = ["ou-82pp-yuxw4n8j"]

    slot_config = {
      org-default = {
        policy_selector          = "default"
        include_account_ids      = ["034034141086"]
        enable_platform_baseline = false
        enable_essential         = false
        enable_anonymous_ip      = false
        enable_bot_control       = false
      }
      alb-external-blue = {
        policy_selector          = "default_include"
        include_account_ids      = []
        enable_platform_baseline = true
        enable_essential         = true
        enable_anonymous_ip      = true
        enable_bot_control       = true
      }
    }

    platform = {
      emergency = {}
      baseline  = {}
    }

    tenants = {}
  }

  assert {
    condition = (
      contains(output.default_policies["org-default"].include_account_ids, "034034141086") &&
      contains(output.default_policies["org-default"].include_orgunit_ids, "ou-82pp-include") &&
      length(output.default_policies["org-default"].exclude_account_ids) == 0 &&
      length(output.default_policies["org-default"].exclude_orgunit_ids) == 0
    )
    error_message = "Include-map slots should receive platform include OUs and omit exclude_map."
  }

  assert {
    condition = (
      length(output.default_policies["alb-external-blue"].include_orgunit_ids) == 0 &&
      contains(output.default_policies["alb-external-blue"].exclude_account_ids, "999999999999") &&
      contains(output.default_policies["alb-external-blue"].exclude_orgunit_ids, "ou-82pp-yuxw4n8j")
    )
    error_message = "Exclude-map slots should ignore platform include lists and keep exclude_map."
  }
}

run "optimize_unassociated_web_acl_org_default_fallback_and_slot_override" {
  command = apply

  variables {
    name_prefix    = "acme"
    environment    = "prod"
    aws_account_id = "111122223333"
    slots          = ["org-default", "alb-external-green", "alb-internal-blue", "alb-external-blue"]

    slot_config = {
      org-default = {
        policy_selector = "default"
        resource_type_list = [
          "AWS::ElasticLoadBalancingV2::LoadBalancer",
          "AWS::ApiGateway::Stage",
        ]
        enable_platform_baseline = false
        enable_essential         = false
        enable_anonymous_ip      = false
        enable_bot_control       = false
      }
      alb-external-green = {
        policy_selector          = "default_include"
        enable_platform_baseline = true
        enable_essential         = true
      }
      alb-internal-blue = {
        policy_selector               = "default_include"
        enable_platform_baseline      = true
        enable_essential              = true
        optimize_unassociated_web_acl = true
      }
      alb-external-blue = {
        policy_selector          = "default_include"
        enable_platform_baseline = true
        enable_essential         = true
      }
    }

    platform = {
      emergency = {}
      baseline  = {}
    }

    tenants = {
      tenant_a = {
        enabled             = true
        enable_bot_control  = false
        tags                = {}
        include_account_ids = ["111122223333"]
        ip_sets = {
          alb-internal-blue = {
            allowlist = ["203.0.113.10/32"]
            blocklist = []
          }
          alb-external-blue = {
            allowlist = ["203.0.113.11/32"]
            blocklist = []
          }
        }
        geo = {}
      }
    }
  }

  assert {
    condition     = jsondecode(output.default_policies["org-default"].managed_service_data).optimizeUnassociatedWebACL == false
    error_message = "org-default must default optimizeUnassociatedWebACL to false so FMS keeps unassociated WebACLs."
  }

  assert {
    condition     = jsondecode(output.default_policies["alb-external-green"].managed_service_data).optimizeUnassociatedWebACL == true
    error_message = "Non-blue slots other than org-default must keep optimizeUnassociatedWebACL=true unless overridden."
  }

  assert {
    condition     = jsondecode(output.default_policies["alb-internal-blue"].managed_service_data).optimizeUnassociatedWebACL == true
    error_message = "slot_config.optimize_unassociated_web_acl must override the blue-slot false fallback."
  }

  assert {
    condition     = jsondecode(output.default_policies["alb-external-blue"].managed_service_data).optimizeUnassociatedWebACL == false
    error_message = "Platform default *-blue slots must keep optimizeUnassociatedWebACL=false unless overridden."
  }

  assert {
    condition     = jsondecode(output.tenant_policies["tenant_a-alb-internal-blue"].managed_service_data).optimizeUnassociatedWebACL == true
    error_message = "Tenant policies must honour slot_config.optimize_unassociated_web_acl for the same slot."
  }

  assert {
    condition     = jsondecode(output.tenant_policies["tenant_a-alb-external-blue"].managed_service_data).optimizeUnassociatedWebACL == true
    error_message = "Tenant policies without a slot override must keep optimizeUnassociatedWebACL=true, including *-blue slots."
  }
}
