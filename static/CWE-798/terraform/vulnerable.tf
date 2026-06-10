# CWE-798: Use of Hard-coded Credentials
# AWS provider is configured with hard-coded access and secret keys committed in source.

provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_db_instance" "app_db" {
  allocated_storage   = 20
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  username            = "dbadmin"
  password            = "SuperSecretP@ssw0rd!"
  skip_final_snapshot = true
}
