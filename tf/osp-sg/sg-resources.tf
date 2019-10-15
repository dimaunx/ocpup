provider "openstack" {
  auth_url         = var.osp_auth_url
  user_name        = var.osp_user_name
  password         = var.osp_user_password
  user_domain_name = var.osp_user_domain_name
  tenant_id        = var.osp_tenant_id
  tenant_name      = var.osp_tenant_name
  region           = var.osp_region
}

data "openstack_networking_port_v2" "apps_port" {
  name = "${var.infra_id}-ingress-port"
}

data "openstack_networking_secgroup_v2" "workers-sg" {
  name = "${var.infra_id}-worker"
}

resource "openstack_networking_floatingip_associate_v2" "apps_fip_association" {
  floating_ip = openstack_networking_floatingip_v2.apps_floating_ip.address
  port_id     = data.openstack_networking_port_v2.apps_port.port_id
}

resource "openstack_networking_secgroup_rule_v2" "worker-vxlan-rule" {
  security_group_id = data.openstack_networking_secgroup_v2.workers-sg.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 4800
  port_range_max    = 4800
  remote_group_id   = data.openstack_networking_secgroup_v2.workers-sg.id
}
