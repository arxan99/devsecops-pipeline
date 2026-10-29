variable "region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "ap-south-1"
}

variable "project" {
  description = "Name prefix for all resources"
  type        = string
  default     = "secure-notes"
}

variable "image_retention_count" {
  description = "Number of tagged images to keep in the registry"
  type        = number
  default     = 20
}
