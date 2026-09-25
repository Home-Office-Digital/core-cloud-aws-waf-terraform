output "policy_id" {
  value = aws_fms_policy.this.id
}

output "policy_name" {
  value = aws_fms_policy.this.name
}

output "include_account_ids" {
  value = var.include_account_ids
}

output "exclude_account_ids" {
  value = var.exclude_account_ids
}
