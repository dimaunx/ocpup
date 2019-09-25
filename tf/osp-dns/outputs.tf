output "api_floating_ip" {
  value = openstack_networking_floatingip_v2.api_floating_ip.address
}