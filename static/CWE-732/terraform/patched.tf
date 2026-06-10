# Remediation for CWE-732: Incorrect Permission Assignment for Critical Resource
# Fix: Scope the IAM policy to least privilege with specific actions and resource ARNs instead of wildcards.

variable "bucket_arn" {
  description = "ARN of the S3 bucket the policy grants access to"
  type        = string
  default     = "arn:aws:s3:::my-app-bucket"
}

resource "aws_iam_policy" "admin_all" {
  name        = "admin-all-access"
  description = "Least-privilege policy scoped to a single bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${var.bucket_arn}/*"
      }
    ]
  })
}
