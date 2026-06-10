# Remediation for CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
# Fix: Set the bucket ACL to private and block all public access at the bucket level.

resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-readable-bucket"
}

resource "aws_s3_bucket_acl" "public_acl" {
  bucket = aws_s3_bucket.public_bucket.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket = aws_s3_bucket.public_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
