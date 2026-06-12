resource "aws_ebs_volume" "app_volume" {
  availability_zone = "us-east-1a"
  size              = 50
  encrypted         = false
}

resource "aws_s3_bucket" "app_bucket" {
  bucket = "my-app-data-bucket"
}
