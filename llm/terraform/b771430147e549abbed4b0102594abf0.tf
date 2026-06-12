resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name                = aws_s3_bucket.trail_bucket.id
  enable_log_file_validation    = false
  include_global_service_events = false
}

resource "aws_s3_bucket" "trail_bucket" {
  bucket = "my-cloudtrail-bucket"
}
