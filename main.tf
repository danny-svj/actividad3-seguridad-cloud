variable "bucket_name" {
  description = "Nombre del bucket simulado"
  type        = string
  default     = "actividad3-seguro-local"
}

# Recurso 1: bucket S3
resource "aws_s3_bucket" "secure_bucket" {
  bucket = var.bucket_name

  tags = {
    Proyecto = "Actividad3-Seguridad"
    Entorno  = "LocalStack"
  }
}

# Recurso 2: cifrado del lado del servidor SSE-S3 (AES-256)
resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Recurso 3: los cuatro controles de bloqueo de acceso público
resource "aws_s3_bucket_public_access_block" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true # rechaza nuevas ACL públicas
  ignore_public_acls      = true # ignora ACL públicas existentes
  block_public_policy     = true # rechaza políticas de bucket públicas
  restrict_public_buckets = true # limita el acceso si hubiera una política pública
}

output "bucket_name" {
  value = aws_s3_bucket.secure_bucket.id
}
