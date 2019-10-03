locals {
  rhcos_ami_id = var.ocp_version == "4.2" ? var.rhcos_ami_id_ocp_4_2 : var.rhcos_ami_id_ocp_4_1
}

module "cl1-aws-infra" {
  source               = "./tf/aws-infra"
  aws_region           = var.aws_region
  infra_id             = var.infra_id
  vpc_cidr             = var.vpc_cidr
  master_instance_type = var.master_instance_type
  rhcos_ami_id         = local.rhcos_ami_id[var.aws_region]
  num_master_nodes     = var.num_master_nodes
  dns_domain           = var.dns_domain
}

module "cl2-aws-infra" {
  source               = "./tf/aws-infra"
  aws_region           = var.aws_region
  infra_id             = var.infra_id
  vpc_cidr             = var.vpc_cidr
  master_instance_type = var.master_instance_type
  rhcos_ami_id         = local.rhcos_ami_id[var.aws_region]
  num_master_nodes     = var.num_master_nodes
  dns_domain           = var.dns_domain
}

module "cl3-aws-infra" {
  source               = "./tf/aws-infra"
  aws_region           = var.aws_region
  infra_id             = var.infra_id
  vpc_cidr             = var.vpc_cidr
  master_instance_type = var.master_instance_type
  rhcos_ami_id         = local.rhcos_ami_id[var.aws_region]
  num_master_nodes     = var.num_master_nodes
  dns_domain           = var.dns_domain
}

module "cl1-aws-bootstrap" {
  source                  = "./tf/aws-bootstrap"
  aws_region              = var.aws_region
  infra_id                = var.infra_id
  bootstrap_instance_type = var.bootstrap_instance_type
  rhcos_ami_id            = local.rhcos_ami_id[var.aws_region]
}

module "cl2-aws-bootstrap" {
  source                  = "./tf/aws-bootstrap"
  aws_region              = var.aws_region
  infra_id                = var.infra_id
  bootstrap_instance_type = var.bootstrap_instance_type
  rhcos_ami_id            = local.rhcos_ami_id[var.aws_region]
}

module "cl3-aws-bootstrap" {
  source                  = "./tf/aws-bootstrap"
  aws_region              = var.aws_region
  infra_id                = var.infra_id
  bootstrap_instance_type = var.bootstrap_instance_type
  rhcos_ami_id            = local.rhcos_ami_id[var.aws_region]
}


module "cl1-aws-workers" {
  source                 = "./tf/aws-workers"
  aws_region             = var.aws_region
  infra_id               = var.infra_id
  rhcos_ami_id           = local.rhcos_ami_id[var.aws_region]
  worker_instance_type   = var.worker_instance_type
  num_worker_nodes       = var.num_worker_nodes
  num_subm_gateway_nodes = var.num_subm_gateway_nodes
}

module "cl2-aws-workers" {
  source                 = "./tf/aws-workers"
  aws_region             = var.aws_region
  infra_id               = var.infra_id
  rhcos_ami_id           = local.rhcos_ami_id[var.aws_region]
  worker_instance_type   = var.worker_instance_type
  num_worker_nodes       = var.num_worker_nodes
  num_subm_gateway_nodes = var.num_subm_gateway_nodes
}

module "cl3-aws-workers" {
  source                 = "./tf/aws-workers"
  aws_region             = var.aws_region
  infra_id               = var.infra_id
  rhcos_ami_id           = local.rhcos_ami_id[var.aws_region]
  worker_instance_type   = var.worker_instance_type
  num_worker_nodes       = var.num_worker_nodes
  num_subm_gateway_nodes = var.num_subm_gateway_nodes
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

