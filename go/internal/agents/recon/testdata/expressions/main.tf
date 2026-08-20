variable "env" {
  type        = string
  default     = "dev"
  description = "environment"
}

variable "count_n" {
  type    = number
  default = 3
}

variable "no_default" {
  type = list(string)
}

output "bucket_arn" {
  value       = aws_s3_bucket.b.arn
  description = "arn"
}

output "plain" {
  value = "hello"
}

provider "google" {
  region = "us-central1"
  alias  = "second"
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.0.0"
  cidr    = "10.0.0.0/16"
}

resource "aws_s3_bucket" "b" {
  bucket        = "x"
  force_destroy = true
  count         = 2
  price         = 1.5
  neg           = -1
  interp        = "${var.env}-suffix"
  cond          = var.env == "dev" ? "a" : "b"
  fn            = lower("ABC")
  lst           = [1, 2, 3]
  obj           = { a = 1, b = "two" }
  nullv         = null
  quoted_key    = { "with space" = 1 }
  ref_list      = [aws_iam_role.r.arn, "literal"]
  local_ref     = local.something
  var_ref       = var.env
  each_ref      = each.key

  versioning {
    enabled = true
  }

  ingress {
    from_port = 1
  }

  ingress {
    from_port = 2
  }

  dynamic "rule" {
    for_each = [1]
    content {
      id = "r"
    }
  }
}

resource "aws_iam_role" "r" {
  name = "role"
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
}

resource "aws_iam_policy" "strings" {
  escaped_newline = "a\nb"
  escaped_slash   = "a\\b"
  escaped_quote   = "a\"b"
  unicode         = "café"
  pure_interp     = "${var.env}"
  heredoc_plain   = <<EOT
line1
line2
EOT
  heredoc_flush = <<-EOT
    {
      "Resource": "${aws_s3_bucket.b.arn}"
    }
  EOT
  heredoc_blank_line = <<-EOT
    a

    b
  EOT
  heredoc_tabs = <<-EOT
		a
			b
	EOT
}
