variable "infra_id" {
  description = "OCP cluster infraid"
}

variable "vpc_cidr" {
  description = "AWS VPC CIDR"
  default     = "10.165.0.0/16"
}

variable "aws_region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "dns_domain" {
  description = "Domain name for public route53 public hosted zone."
  default     = "devcluster.openshift.com"
}

variable "public_network_name" {
  description = "Public network name"
  default     = "public"
}

variable "rhcos_ami_id_ocp_4_1" {
  description = "Current Red Hat Enterprise Linux CoreOS AMI to use for boostrap and ocp 4.1 nodes. rhcos-410.8.20190520.0-hvm"
  type        = "map"
  default = {
    "us-east-1" = "ami-046fe691f52a953f9"
    "us-east-2" = "ami-0649fd5d42859bdfc"
    "us-west-2" = "ami-00745fcbb14a863ed"
  }
}

variable "rhcos_ami_id_ocp_4_2" {
  description = "Current Red Hat Enterprise Linux CoreOS AMI to use for boostrap and ocp 4.2 nodes. rhcos-42.80.20190725.1-hvm"
  type        = "map"
  default = {
    "us-east-1" = "ami-0ae2df22579e00be5"
    "us-east-2" = "ami-01309f148f8cfae82"
    "us-west-2" = "ami-07c648fffd195d6d9"
  }
}

variable "ocp_version" {
  description = "The version of OCP clusters you are installing."
  default     = "4.2"
}

variable "bootstrap_instance_type" {
  description = "Bootstrap instance size"
  default     = "i3.large"
}

variable "master_instance_type" {
  description = "Master instance size"
  default     = "m4.xlarge"
}
variable "worker_instance_type" {
  description = "Master instance size"
  default     = "m4.large"
}

variable "num_master_nodes" {
  description = "Number of worker nodes. Please do not modify. Controlled by ocpup.yaml"
  default     = 0
}

variable "num_worker_nodes" {
  description = "Number of worker nodes. Please do not modify. Controlled by ocpup.yaml"
  default     = 0
}

variable "num_subm_gateway_nodes" {
  description = "Number of workers to act like submariner gateway node. Please do not modify. Controlled by ocpup.yaml"
  default     = 0
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