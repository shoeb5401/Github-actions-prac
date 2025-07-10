output "writeonly_instance_id" {
  value = aws_instance.writeonly_instance.id
}

output "writeonly_instance_public_ip" {
  value = aws_instance.writeonly_instance.public_ip
}

output "readonly_instance_id" {
  value = aws_instance.readonly_instance.id
}

output "readonly_instance_public_ip" {
  value = aws_instance.readonly_instance.public_ip
}

output "private_key_file" {
  description = "Path to the generated private key file"
  value       = local_file.private_key.filename
}

output "key_pair_name" {
  value = aws_key_pair.assignment.key_name
}

output "s3_readonly_role_arn" {
  value = aws_iam_role.s3_readonly_role.arn
}

output "s3_writeonly_role_arn" {
  value = aws_iam_role.s3_writeonly_role.arn
}

output "s3_bucket_name" {
  value = aws_s3_bucket.log_bucket.id
}
