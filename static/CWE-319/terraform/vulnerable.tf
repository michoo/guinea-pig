# CWE-319: Cleartext Transmission of Sensitive Information
# Load balancer listener serves traffic over plaintext HTTP and DB is publicly accessible without encryption.

resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.example.arn
  port              = 80
  protocol          = "HTTP"

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
  port     = 80
  protocol = "HTTP"
  vpc_id   = "vpc-12345678"
}

resource "aws_db_instance" "cleartext_db" {
  allocated_storage   = 20
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = "changeme123"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}
