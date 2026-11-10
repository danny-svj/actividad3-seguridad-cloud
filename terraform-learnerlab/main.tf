# Variante para AWS Academy Learner Lab.
# El SCP del laboratorio niega s3:GetBucketObjectLockConfiguration, que el recurso
# aws_s3_bucket del provider lee siempre. Por eso Terraform gestiona el bucket mediante
# un stack de CloudFormation con la MISMA configuración segura que ../terraform/main.tf.
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
  region = "us-east-1"
}

variable "bucket_name" {
  type    = string
  default = "actividad3-seguro-2024-dags"
}

resource "aws_cloudformation_stack" "secure_bucket" {
  name = "actividad3-secure-bucket"
  template_body = jsonencode({
    AWSTemplateFormatVersion = "2010-09-09"
    Resources = {
      SecureBucket = {
        Type = "AWS::S3::Bucket"
        Properties = {
          BucketName = var.bucket_name
          # Cifrado del lado del servidor AES-256 (SSE-S3)
          BucketEncryption = {
            ServerSideEncryptionConfiguration = [{
              ServerSideEncryptionByDefault = { SSEAlgorithm = "AES256" }
            }]
          }
          # Bloqueo total de acceso público
          PublicAccessBlockConfiguration = {
            BlockPublicAcls       = true
            BlockPublicPolicy     = true
            IgnorePublicAcls      = true
            RestrictPublicBuckets = true
          }
          # ACLs deshabilitadas (equivalente a acl = "private")
          OwnershipControls = {
            Rules = [{ ObjectOwnership = "BucketOwnerEnforced" }]
          }
          VersioningConfiguration = { Status = "Enabled" }
          Tags                    = [{ Key = "Proyecto", Value = "Actividad3-Seguridad" }]
        }
      }
      # Política: deniega cualquier acceso sin TLS
      SecureBucketPolicy = {
        Type = "AWS::S3::BucketPolicy"
        Properties = {
          Bucket = { Ref = "SecureBucket" }
          PolicyDocument = {
            Version = "2012-10-17"
            Statement = [{
              Sid       = "DenyInsecureTransport"
              Effect    = "Deny"
              Principal = "*"
              Action    = "s3:*"
              Resource = [
                { "Fn::GetAtt" = ["SecureBucket", "Arn"] },
                { "Fn::Join" = ["", [{ "Fn::GetAtt" = ["SecureBucket", "Arn"] }, "/*"]] }
              ]
              Condition = { Bool = { "aws:SecureTransport" = "false" } }
            }]
          }
        }
      }
    }
    Outputs = {
      BucketName = { Value = { Ref = "SecureBucket" } }
    }
  })
}

output "bucket_name" {
  value = aws_cloudformation_stack.secure_bucket.outputs["BucketName"]
}
