# ============================================================================
# 1. GitHub Actions IAM OIDC Identity Provider
# ============================================================================
resource "aws_iam_openid_connect_provider" "github_actions" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd"
  ]
}

# ============================================================================
# 2. Dedicated Least-Privilege Deployment Role (GitHub Actions OIDC)
# ============================================================================
data "aws_iam_policy_document" "github_deploy_trust" {
  statement {
    sid     = "AllowGitHubActionsOIDCExactRepoAndBranch"
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/${var.github_branch}",
        "repo:${var.github_org}/${var.github_repo}:environment:${var.github_environment}",
        "repo:${var.github_org}@210805622/${var.github_repo}@1428816555:ref:refs/heads/${var.github_branch}",
        "repo:${var.github_org}@210805622/${var.github_repo}@1428816555:environment:${var.github_environment}"
      ]
    }
  }
}

resource "aws_iam_role" "github_deploy" {
  name                 = local.deploy_role_name
  description          = "Dedicated least-privilege CI/CD deployment role for ${var.github_org}/${var.github_repo}"
  assume_role_policy   = data.aws_iam_policy_document.github_deploy_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "github_deploy_least_privilege" {
  statement {
    sid    = "ManageZeroGateS3Buckets"
    effect = "Allow"
    actions = [
      "s3:CreateBucket",
      "s3:GetBucketLocation",
      "s3:GetBucketPolicy",
      "s3:PutBucketPolicy",
      "s3:DeleteBucketPolicy",
      "s3:GetBucketPublicAccessBlock",
      "s3:PutBucketPublicAccessBlock",
      "s3:GetEncryptionConfiguration",
      "s3:PutEncryptionConfiguration",
      "s3:GetBucketVersioning",
      "s3:PutBucketVersioning",
      "s3:GetBucketOwnershipControls",
      "s3:PutBucketOwnershipControls",
      "s3:GetLifecycleConfiguration",
      "s3:PutLifecycleConfiguration",
      "s3:GetBucketTagging",
      "s3:PutBucketTagging",
      "s3:ListBucket",
      "s3:GetObject",
      "s3:PutObject",
      "s3:GetObjectTagging",
      "s3:PutObjectTagging"
    ]
    resources = [
      "arn:${local.partition}:s3:::${local.lab_bucket_name}",
      "arn:${local.partition}:s3:::${local.lab_bucket_name}/*",
      "arn:${local.partition}:s3:::${local.trail_bucket_name}",
      "arn:${local.partition}:s3:::${local.trail_bucket_name}/*"
    ]
  }

  statement {
    sid    = "ManageZeroGateCloudTrail"
    effect = "Allow"
    actions = [
      "cloudtrail:CreateTrail",
      "cloudtrail:UpdateTrail",
      "cloudtrail:GetTrail",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:GetEventSelectors",
      "cloudtrail:PutEventSelectors",
      "cloudtrail:StartLogging",
      "cloudtrail:StopLogging",
      "cloudtrail:ListTags",
      "cloudtrail:AddTags"
    ]
    resources = [
      "arn:${local.partition}:cloudtrail:${var.aws_region}:${local.account_id}:trail/${local.trail_name}"
    ]
  }

  statement {
    sid    = "InspectZeroGateIAMAndOIDC"
    effect = "Allow"
    actions = [
      "iam:GetOpenIDConnectProvider",
      "iam:GetRole",
      "iam:GetRolePolicy",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies"
    ]
    resources = [
      aws_iam_openid_connect_provider.github_actions.arn,
      "arn:${local.partition}:iam::${local.account_id}:role/${local.deploy_role_name}",
      "arn:${local.partition}:iam::${local.account_id}:role/${local.analyst_role_name}"
    ]
  }

  statement {
    sid    = "ManageZeroGateMonthlyBudget"
    effect = "Allow"
    actions = [
      "budgets:ViewBudget",
      "budgets:ModifyBudget"
    ]
    resources = [
      "arn:${local.partition}:budgets::${local.account_id}:budget/${local.budget_name}"
    ]
  }
}

resource "aws_iam_role_policy" "github_deploy_least_privilege" {
  name   = "${var.project_name}-deploy-least-privilege"
  role   = aws_iam_role.github_deploy.id
  policy = data.aws_iam_policy_document.github_deploy_least_privilege.json
}

# ============================================================================
# 3. Optional Keycloak OIDC Provider & Separate Read-Only Analyst Role
# ============================================================================
resource "aws_iam_openid_connect_provider" "keycloak" {
  count          = var.enable_keycloak_oidc && var.keycloak_issuer_url != "" ? 1 : 0
  url            = var.keycloak_issuer_url
  client_id_list = ["sts.amazonaws.com", "zerogate-aws-analyst"]
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1"
  ]
}

data "aws_iam_policy_document" "readonly_analyst_trust" {
  dynamic "statement" {
    for_each = var.enable_keycloak_oidc && var.keycloak_issuer_url != "" ? [1] : []
    content {
      sid     = "AllowKeycloakOIDCFederatedAnalyst"
      effect  = "Allow"
      actions = ["sts:AssumeRoleWithWebIdentity"]

      principals {
        type        = "Federated"
        identifiers = [aws_iam_openid_connect_provider.keycloak[0].arn]
      }

      condition {
        test     = "StringEquals"
        variable = "${replace(var.keycloak_issuer_url, "https://", "")}:aud"
        values   = ["sts.amazonaws.com"]
      }

      condition {
        test     = "StringEquals"
        variable = "${replace(var.keycloak_issuer_url, "https://", "")}:sub"
        values   = ["analyst:bob_analyst"]
      }
    }
  }

  statement {
    sid     = "AllowControlledLabAnalystSessionWithExternalId"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [data.aws_caller_identity.current.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = ["zerogate-analyst-session-v1"]
    }
  }
}

resource "aws_iam_role" "readonly_analyst" {
  name                 = local.analyst_role_name
  description          = "Separate read-only security analyst and DLP inspection role"
  assume_role_policy   = data.aws_iam_policy_document.readonly_analyst_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "readonly_analyst_least_privilege" {
  statement {
    sid    = "ReadOnlyS3LabDLPInspection"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:GetBucketLocation",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetEncryptionConfiguration",
      "s3:GetBucketPolicy",
      "s3:GetBucketVersioning"
    ]
    resources = [
      "arn:${local.partition}:s3:::${local.lab_bucket_name}",
      "arn:${local.partition}:s3:::${local.lab_bucket_name}/*"
    ]
  }

  statement {
    sid    = "ReadOnlyCloudTrailInspection"
    effect = "Allow"
    actions = [
      "cloudtrail:GetTrail",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:GetEventSelectors"
    ]
    resources = [
      "arn:${local.partition}:cloudtrail:${var.aws_region}:${local.account_id}:trail/${local.trail_name}"
    ]
  }
}

resource "aws_iam_role_policy" "readonly_analyst_least_privilege" {
  name   = "${var.project_name}-analyst-readonly-policy"
  role   = aws_iam_role.readonly_analyst.id
  policy = data.aws_iam_policy_document.readonly_analyst_least_privilege.json
}
