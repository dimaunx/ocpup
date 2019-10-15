variable "infra_id" {
  description = "OCP cluster infraid"
}

variable "aws_region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "num_gateways" {
  description = "The number of submariner gateways."
  default      = 1
}

variable "dns_domain" {
  description = "Domain name for public route53 public hosted zone."
  default     = "devcluster.openshift.com"
}

variable "public_network_name" {
  description = "Public network name"
  default     = "public"
}

variable "osp_auth_url" {
  description = "OS auth url"
  default     = "https://test/v3"
}

variable "osp_user_name" {
  description = "OS user name"
  default     = "user"
}

variable "osp_user_password" {
  description = "OS user password"
  default     = "password"
}

variable "osp_user_domain_name" {
  description = "OS user domain name"
  default     = "redhat.com"
}

variable "osp_tenant_id" {
  description = "OS tennant id"
  default     = "some_id"
}

variable "osp_tenant_name" {
  description = "OS tennant name"
  default     = "some_tenant"
}

variable "osp_region" {
  description = "OS region"
  default     = "regionOne"
}