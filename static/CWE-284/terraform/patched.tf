# Remediation for CWE-284: Improper Access Control
# Fix: Restrict SSH ingress to a specific trusted CIDR and remove the open 0.0.0.0/0 allow-all rule.

variable "trusted_cidr" {
  description = "Trusted CIDR allowed to reach SSH"
  type        = string
  default     = "10.0.0.0/24"
}

resource "aws_security_group" "open_sg" {
  name        = "open-ingress"
  description = "Allows restricted inbound access"

  ingress {
    description = "SSH from trusted network only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.trusted_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
