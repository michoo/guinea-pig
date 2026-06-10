# Remediation for CWE-778: Insufficient Logging
# Fix: Enable CloudTrail log file validation, global service events, and S3 server access logging.

resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name                = aws_s3_bucket.trail_bucket.id
  enable_log_file_validation    = true
  include_global_service_events = true
}

resource "aws_s3_bucket" "trail_bucket" {
  bucket = "my-cloudtrail-bucket-no-logging"
}

resource "aws_s3_bucket" "log_bucket" {
  bucket = "my-cloudtrail-access-logs"
}

resource "aws_s3_bucket_logging" "trail_logging" {
  bucket = aws_s3_bucket.trail_bucket.id

  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "log/"
}
