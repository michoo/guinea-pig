# Remediation for CWE-798: Use of Hard-coded Credentials
# Fix: Remove hard-coded AWS keys (use the default credential chain / instance profile) and source the DB password from a sensitive variable.

variable "db_password" {
  description = "Database master password supplied at runtime"
  type        = string
  sensitive   = true
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_db_instance" "app_db" {
  allocated_storage   = 20
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  username            = "dbadmin"
  password            = var.db_password
  skip_final_snapshot = true
}
