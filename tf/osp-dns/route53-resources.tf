provider "aws" {
  region = var.aws_region
}

provider "openstack" {
  auth_url         = var.osp_auth_url
  user_name        = var.osp_user_name
  password         = var.osp_user_password
  user_domain_name = var.osp_user_domain_name
  tenant_id        = var.osp_tenant_id
  tenant_name      = var.osp_tenant_name
  region           = var.osp_region
}

data "aws_route53_zone" "public_zone" {
  name         = var.dns_domain
  private_zone = false
}

resource "openstack_networking_floatingip_v2" "api_floating_ip" {
  pool        = var.public_network_name
  description = "${var.infra_id} api fip"
}

# Create api external alias
resource "aws_route53_record" "api_dns_record" {
  zone_id         = data.aws_route53_zone.public_zone.id
  name            = "api.${var.infra_id}"
  type            = "A"
  ttl             = "60"
  records         = ["${openstack_networking_floatingip_v2.api_floating_ip.address}"]
  allow_overwrite = true
}