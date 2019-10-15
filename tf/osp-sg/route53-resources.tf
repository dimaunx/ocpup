provider "aws" {
  region = var.aws_region
}

data "aws_route53_zone" "public_zone" {
  name         = var.dns_domain
  private_zone = false
}

# Create api external alias
locals {
  records_base = join("-", slice(split("-", var.infra_id), 0, 2))
}

resource "openstack_networking_floatingip_v2" "apps_floating_ip" {
  pool        = var.public_network_name
  description = "${var.infra_id} apps fip"
}

resource "aws_route53_record" "apps_dns_record" {
  zone_id         = data.aws_route53_zone.public_zone.id
  name            = "*.apps.${local.records_base}"
  type            = "A"
  ttl             = "60"
  records         = ["${openstack_networking_floatingip_v2.apps_floating_ip.address}"]
  allow_overwrite = true
}