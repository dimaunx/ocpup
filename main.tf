module "cl1-aws-ipi" {
  source     = "./tf/aws-ipi"
  infra_id   = var.infra_id
  aws_region = var.aws_region

}

module "cl2-aws-ipi" {
  source     = "./tf/aws-ipi"
  infra_id   = var.infra_id
  aws_region = var.aws_region

}

module "cl3-aws-ipi" {
  source     = "./tf/aws-ipi"
  infra_id   = var.infra_id
  aws_region = var.aws_region

}

module "cl1-osp-dns" {
  source               = "./tf/osp-dns"
  aws_region           = var.aws_region
  dns_domain           = var.dns_domain
  infra_id             = var.infra_id
  public_network_name  = var.public_network_name
  osp_auth_url         = var.osp_auth_url
  osp_tenant_id        = var.osp_tenant_id
  osp_tenant_name      = var.osp_tenant_name
  osp_user_name        = var.osp_user_name
  osp_user_password    = var.osp_user_password
  osp_user_domain_name = var.osp_user_domain_name
  osp_region           = var.osp_region
}

module "cl2-osp-dns" {
  source               = "./tf/osp-dns"
  aws_region           = var.aws_region
  dns_domain           = var.dns_domain
  infra_id             = var.infra_id
  public_network_name  = var.public_network_name
  osp_auth_url         = var.osp_auth_url
  osp_tenant_id        = var.osp_tenant_id
  osp_tenant_name      = var.osp_tenant_name
  osp_user_name        = var.osp_user_name
  osp_user_password    = var.osp_user_password
  osp_user_domain_name = var.osp_user_domain_name
  osp_region           = var.osp_region
}

module "cl3-osp-dns" {
  source               = "./tf/osp-dns"
  aws_region           = var.aws_region
  dns_domain           = var.dns_domain
  infra_id             = var.infra_id
  public_network_name  = var.public_network_name
  osp_auth_url         = var.osp_auth_url
  osp_tenant_id        = var.osp_tenant_id
  osp_tenant_name      = var.osp_tenant_name
  osp_user_name        = var.osp_user_name
  osp_user_password    = var.osp_user_password
  osp_user_domain_name = var.osp_user_domain_name
  osp_region           = var.osp_region
}

module "cl1-osp-sg" {
  source               = "./tf/osp-sg"
  aws_region           = var.aws_region
  infra_id             = var.infra_id
  dns_domain           = var.dns_domain
  osp_auth_url         = var.osp_auth_url
  osp_tenant_id        = var.osp_tenant_id
  osp_tenant_name      = var.osp_tenant_name
  osp_user_name        = var.osp_user_name
  osp_user_password    = var.osp_user_password
  osp_user_domain_name = var.osp_user_domain_name
  osp_region           = var.osp_region
  public_network_name  = var.public_network_name
}

module "cl2-osp-sg" {
  source               = "./tf/osp-sg"
  aws_region           = var.aws_region
  infra_id             = var.infra_id
  dns_domain           = var.dns_domain
  osp_auth_url         = var.osp_auth_url
  osp_tenant_id        = var.osp_tenant_id
  osp_tenant_name      = var.osp_tenant_name
  osp_user_name        = var.osp_user_name
  osp_user_password    = var.osp_user_password
  osp_user_domain_name = var.osp_user_domain_name
  osp_region           = var.osp_region
  public_network_name  = var.public_network_name
}

module "cl3-osp-sg" {
  source               = "./tf/osp-sg"
  aws_region           = var.aws_region
  infra_id             = var.infra_id
  dns_domain           = var.dns_domain
  osp_auth_url         = var.osp_auth_url
  osp_tenant_id        = var.osp_tenant_id
  osp_tenant_name      = var.osp_tenant_name
  osp_user_name        = var.osp_user_name
  osp_user_password    = var.osp_user_password
  osp_user_domain_name = var.osp_user_domain_name
  osp_region           = var.osp_region
  public_network_name  = var.public_network_name
}

