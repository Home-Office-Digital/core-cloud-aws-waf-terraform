mock_provider "aws" {}

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
        enabled            = true
        enable_bot_control = false
        tags               = {}
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
        core_rule_set_override_action = "COUNT"
      }
    }

    platform = {
      baseline  = {}
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
}