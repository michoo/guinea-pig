# Remediation for CWE-311: Missing Encryption of Sensitive Data
# Fix: Enable encryption at rest for the EBS volume and apply S3 server-side encryption (SSE).

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 50
  encrypted         = true
}

resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "my-unencrypted-data-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sse" {
  bucket = aws_s3_bucket.unencrypted_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
