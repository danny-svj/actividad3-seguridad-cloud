terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  type    = string
  default = "us-east-1"
}

# Los nombres de bucket son globales: si "actividad3-seguro-2024" ya existe,
# cambia este valor (ej. agregando tus iniciales).
variable "bucket_name" {
  type    = string
  default = "actividad3-seguro-2024-dags"
}

# AWS Academy Learner Lab no permite iam:CreateRole. Ponlo en true en una cuenta normal.
variable "create_iam_role" {
  type    = bool
  default = false
}

# 1. Bucket S3
resource "aws_s3_bucket" "secure_bucket" {
  bucket = var.bucket_name
  tags = {
    Proyecto = "Actividad3-Seguridad"
  }
}

# 2. Propiedad de objetos: deshabilita ACLs (equivalente moderno a acl = "private")
resource "aws_s3_bucket_ownership_controls" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# 3. Cifrado del lado del servidor con AES-256 (SSE-S3)
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# 4. Bloqueo total de acceso público
resource "aws_s3_bucket_public_access_block" "secure_bucket" {
  bucket                  = aws_s3_bucket.secure_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 5. Versionado (protege contra borrado/sobrescritura accidental)
resource "aws_s3_bucket_versioning" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

# 6. Política de bucket: solo HTTPS (rechaza tráfico sin TLS)
resource "aws_s3_bucket_policy" "secure_bucket" {
  bucket     = aws_s3_bucket.secure_bucket.id
  depends_on = [aws_s3_bucket_public_access_block.secure_bucket]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.secure_bucket.arn,
        "${aws_s3_bucket.secure_bucket.arn}/*"
      ]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# 7. Rol IAM de mínimo privilegio: solo lectura de objetos del bucket
resource "aws_iam_role" "app_reader" {
  count = var.create_iam_role ? 1 : 0
  name  = "actividad3-app-reader"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "s3_read_only" {
  count  = var.create_iam_role ? 1 : 0
  name   = "actividad3-s3-getobject"
  role   = aws_iam_role.app_reader[0].id
  policy = templatefile("${path.module}/iam-policy.json", { bucket = var.bucket_name })
}

output "bucket_name" {
  value = aws_s3_bucket.secure_bucket.id
}

output "reader_role_arn" {
  value = var.create_iam_role ? aws_iam_role.app_reader[0].arn : "no creado (Learner Lab)"
}
