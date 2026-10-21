# ============================================================================
# Private S3 Lab Bucket for Synthetic DLP Scanning
# ============================================================================
resource "aws_s3_bucket" "dlp_lab" {
  bucket        = local.lab_bucket_name
  force_destroy = false
}

resource "aws_s3_bucket_ownership_controls" "dlp_lab" {
  bucket = aws_s3_bucket.dlp_lab.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "dlp_lab" {
  bucket                  = aws_s3_bucket.dlp_lab.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "dlp_lab" {
  bucket = aws_s3_bucket.dlp_lab.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "dlp_lab" {
  bucket = aws_s3_bucket.dlp_lab.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "dlp_lab" {
  bucket = aws_s3_bucket.dlp_lab.id

  rule {
    id     = "expire-temp-lab-objects-30d"
    status = "Enabled"

    filter {}

    expiration {
      days = 30
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "dlp_lab_enforce_https" {
  statement {
    sid     = "DenyInsecureHTTPTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    resources = [
      aws_s3_bucket.dlp_lab.arn,
      "${aws_s3_bucket.dlp_lab.arn}/*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "dlp_lab_enforce_https" {
  bucket     = aws_s3_bucket.dlp_lab.id
  policy     = data.aws_iam_policy_document.dlp_lab_enforce_https.json
  depends_on = [aws_s3_bucket_public_access_block.dlp_lab]
}

# ============================================================================
# Synthetic Test Object for Read-Only Cloud DLP Verification
# ============================================================================
resource "aws_s3_object" "synthetic_dlp_sample" {
  bucket                 = aws_s3_bucket.dlp_lab.id
  key                    = "samples/synthetic_onboarding_record.txt"
  content_type           = "text/plain"
  server_side_encryption = "AES256"
  content                = <<-EOT
    ====================================================================
    ZEROGATE CLOUD LAB — SYNTHETIC TEST FIXTURE ONLY (NOT REAL PII)
    ====================================================================
    Record ID       : ZG-SYNTH-2026-0042
    Synthetic Aadhaar: 2345 6789 0124
    Synthetic PAN    : ABCPE1234F
    Canary Token     : zg_test_9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d
    Department       : Cloud Security Engineering Lab
    ====================================================================
  EOT

  depends_on = [
    aws_s3_bucket_server_side_encryption_configuration.dlp_lab,
    aws_s3_bucket_public_access_block.dlp_lab
  ]
}
