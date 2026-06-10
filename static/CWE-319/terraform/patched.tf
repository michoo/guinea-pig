# Remediation for CWE-319: Cleartext Transmission of Sensitive Information
# Fix: Serve traffic over an HTTPS listener with a TLS certificate, encrypt DB storage, and make the DB non-public.

variable "certificate_arn" {
  description = "ACM certificate ARN for the HTTPS listener"
  type        = string
}

variable "db_password" {
  description = "Database master password"
  type        = string
  sensitive   = true
}

resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.example.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.example.arn
  }
}

resource "aws_lb" "example" {
  name               = "example-lb"
  internal           = false
  load_balancer_type = "application"
  subnets            = ["subnet-12345678", "subnet-87654321"]
}

resource "aws_lb_target_group" "example" {
  name     = "example-tg"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = "vpc-12345678"
}

resource "aws_db_instance" "cleartext_db" {
  allocated_storage   = 20
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = var.db_password
  publicly_accessible = false
  storage_encrypted   = true
  skip_final_snapshot = true
}
