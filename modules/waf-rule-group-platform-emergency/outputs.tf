output "rule_group_arn" {
  value = aws_wafv2_rule_group.this.arn
}

output "rule_group_name" {
  value = aws_wafv2_rule_group.this.name
}

output "rule_group_id" {
  value = aws_wafv2_rule_group.this.id
}