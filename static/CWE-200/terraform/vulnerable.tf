# CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
# S3 bucket ACL is set to public-read, exposing stored objects to anyone on the internet.

resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-readable-bucket"
}

resource "aws_s3_bucket_acl" "public_acl" {
  bucket = aws_s3_bucket.public_bucket.id
  acl    = "public-read"
}
