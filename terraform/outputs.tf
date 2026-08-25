output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = aws_eks_cluster.example.endpoint
}

output "node_group_name" {
  description = "EKS node group name"
  value       = aws_eks_node_group.example.name
}

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.example.id
}