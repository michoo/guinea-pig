# CWE-284: Improper Access Control
# Security group allows inbound SSH and all traffic from any IP address (0.0.0.0/0).

resource "aws_security_group" "open_sg" {
  name        = "open-ingress"
  description = "Allows unrestricted inbound access"

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "All ports from anywhere"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
