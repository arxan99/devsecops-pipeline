output "ecr_repository_url" {
  description = "Registry URL to push the application image to"
  value       = aws_ecr_repository.app.repository_url
}

output "log_bucket" {
  description = "Encrypted, private bucket for audit and access logs"
  value       = aws_s3_bucket.logs.id
}

output "kms_key_arn" {
  description = "KMS key protecting the registry and log bucket"
  value       = aws_kms_key.main.arn
}
