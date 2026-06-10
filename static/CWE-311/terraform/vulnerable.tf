# CWE-311: Missing Encryption of Sensitive Data
# EBS volume is created without encryption enabled, storing data at rest in cleartext.

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 50
  encrypted         = false
}

resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "my-unencrypted-data-bucket"
}
