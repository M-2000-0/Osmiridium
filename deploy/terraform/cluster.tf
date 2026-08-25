module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"

  cluster_name    = var.cluster_name
  cluster_version = "1.29"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  eks_managed_node_groups = {
    osmiridium = {
      min_size       = 2
      max_size       = 6
      desired_size   = 3
      instance_types = ["t3.medium"]
      capacity_type  = "ON_DEMAND"
    }
  }

  cluster_addons = {
    coredns    = {}
    kube-proxy = {}
    vpc-cni    = {}
  }
}

resource "kubernetes_namespace" "osmiridium" {
  metadata {
    name = "osmiridium"
    labels = {
      "app.kubernetes.io/name" = "osmiridium"
    }
  }
  depends_on = [module.eks]
}
