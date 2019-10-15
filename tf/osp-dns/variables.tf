variable "public_network_name" {
  description = "Public network name to allocate floating ips."
}

variable "infra_id" {
  description = "OCP cluster infra id"
}

variable "dns_domain" {
  description = "OCP cluster  base dns name."
}

variable "aws_region" {
  description = "aws region"
}

variable "osp_auth_url" {
  description = "OS auth url"
}

variable "osp_user_name" {
  description = "OS user name"
}

variable "osp_user_password" {
  description = "OS user password"
}

variable "osp_user_domain_name" {
  description = "OS user domain name"
}

variable "osp_tenant_id" {
  description = "OS tennant id"
}

variable "osp_tenant_name" {
  description = "OS tennant name"
}

variable "osp_region" {
  description = "OS region"
}
