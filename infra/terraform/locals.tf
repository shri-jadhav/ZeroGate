data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

locals {
  account_id        = data.aws_caller_identity.current.account_id
  partition         = data.aws_partition.current.partition
  lab_bucket_name   = "${var.project_name}-dlp-lab-${local.account_id}-${var.aws_region}"
  trail_bucket_name = "${var.project_name}-cloudtrail-${local.account_id}-${var.aws_region}"
  trail_name        = "${var.project_name}-${var.environment}-management-trail"
  deploy_role_name  = "${var.project_name}-${var.environment}-github-deploy-role"
  analyst_role_name = "${var.project_name}-${var.environment}-readonly-analyst-role"
  budget_name       = "${var.project_name}-${var.environment}-monthly-budget"
}
