output "aws_account_id" {
  description = "Active AWS Account ID"
  value       = local.account_id
}

output "aws_region" {
  description = "Deployed AWS Region"
  value       = var.aws_region
}

output "github_oidc_provider_arn" {
  description = "ARN of the GitHub Actions IAM OIDC Provider"
  value       = aws_iam_openid_connect_provider.github_actions.arn
}

output "github_deploy_role_arn" {
  description = "ARN of the least-privilege GitHub Actions deployment role"
  value       = aws_iam_role.github_deploy.arn
}

output "readonly_analyst_role_arn" {
  description = "ARN of the separate read-only security analyst & DLP inspection role"
  value       = aws_iam_role.readonly_analyst.arn
}

output "dlp_lab_bucket_name" {
  description = "Name of the private S3 lab bucket containing synthetic DLP test data"
  value       = aws_s3_bucket.dlp_lab.id
}

output "dlp_lab_bucket_arn" {
  description = "ARN of the private S3 lab bucket"
  value       = aws_s3_bucket.dlp_lab.arn
}

output "cloudtrail_bucket_name" {
  description = "Name of the private S3 bucket storing CloudTrail management logs"
  value       = aws_s3_bucket.cloudtrail_logs.id
}

output "cloudtrail_trail_arn" {
  description = "ARN of the ZeroGate CloudTrail management trail"
  value       = aws_cloudtrail.zerogate_audit.arn
}

output "budget_name" {
  description = "Name of the monthly AWS Cost Budget guard"
  value       = aws_budgets_budget.zerogate_monthly.name
}
