variable "aws_region" {
  description = "AWS region for ZeroGate Cloud lab deployment"
  type        = string
  default     = "ap-south-1"
}

variable "project_name" {
  description = "Project prefix for uniquely naming ZeroGate Cloud resources"
  type        = string
  default     = "zerogate-cloud"
}

variable "environment" {
  description = "Deployment environment identifier"
  type        = string
  default     = "lab"
}

variable "github_org" {
  description = "GitHub organization or owner allowed in OIDC trust policy"
  type        = string
  default     = "shri-jadhav"
}

variable "github_repo" {
  description = "GitHub repository name allowed in OIDC trust policy"
  type        = string
  default     = "ZeroGate"
}

variable "github_branch" {
  description = "Protected GitHub branch permitted to assume deployment role"
  type        = string
  default     = "main"
}

variable "github_environment" {
  description = "Protected GitHub environment permitted to assume deployment role"
  type        = string
  default     = "production"
}

variable "budget_limit_usd" {
  description = "Monthly AWS Budget alert threshold in USD (strictly within $200 credit budget)"
  type        = string
  default     = "10.0"
}

variable "budget_alert_emails" {
  description = "Optional email addresses for AWS Budget threshold alerts"
  type        = list(string)
  default     = []
}

variable "enable_guardduty" {
  description = "Explicit opt-in gate for Amazon GuardDuty (disabled by default due to subscription/cost review)"
  type        = bool
  default     = false
}

variable "enable_keycloak_oidc" {
  description = "Explicit opt-in gate for Keycloak IAM OIDC provider (requires publicly reachable HTTPS issuer)"
  type        = bool
  default     = false
}

variable "keycloak_issuer_url" {
  description = "Publicly reachable HTTPS Keycloak realm issuer URL (only used if enable_keycloak_oidc is true)"
  type        = string
  default     = ""
}
