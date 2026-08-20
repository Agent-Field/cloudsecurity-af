provider "aws" {
  region = "us-east-1"
}

# 1. The Public Entry Point (Vulnerable)
resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  iam_instance_profile = aws_iam_instance_profile.web_profile.name

  # Publicly accessible
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.allow_all.id]

  tags = {
    Name = "PublicWebServer"
  }
}

resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 2. The Over-Permissive IAM Role (The Pivot)
resource "aws_iam_role" "web_role" {
  name = "web_server_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "web_profile" {
  name = "web_server_profile"
  role = aws_iam_role.web_role.name
}

resource "aws_iam_role_policy" "s3_full_access" {
  name = "s3_full_access_policy"
  role = aws_iam_role.web_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:*"
        ]
        Effect   = "Allow"
        Resource = [
          aws_s3_bucket.customer_data.arn,
          "${aws_s3_bucket.customer_data.arn}/*"
        ]
      }
    ]
  })
}

# 3. The Sensitive Data (The Target)
resource "aws_s3_bucket" "customer_data" {
  bucket = "company-customer-pii-data-2025"
}

resource "aws_s3_bucket_public_access_block" "customer_data_block" {
  bucket = aws_s3_bucket.customer_data.id

  # Vulnerable: Not blocking public access
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
