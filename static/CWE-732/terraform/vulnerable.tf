# CWE-732: Incorrect Permission Assignment for Critical Resource
# IAM policy grants all actions on all resources (wildcard admin), violating least privilege.

resource "aws_iam_policy" "admin_all" {
  name        = "admin-all-access"
  description = "Overly permissive policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["*"]
        Resource = "*"
      }
    ]
  })
}
