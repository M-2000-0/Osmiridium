# Kubernetes Deployment — unshipped - coming soon

This directory is reserved for Kubernetes manifests for Osmiridium.

**Status:** Not yet shipped — unshipped - coming soon. The current deployment path is Docker Compose (see `docker-compose.yml` at the repository root) and bare-metal via `cargo build --release`.

When Kubernetes support is added, this directory will contain:
- `namespace.yaml`
- `deployment.yaml` (coordinator + party sets)
- `service.yaml`
- `configmap.yaml` / `secret.yaml`
- `ingress.yaml`
- `networkpolicy.yaml`
- Helm chart under `helm/`

Tracking: LAUNCH_READINESS.md items 705-772.

Until then, do not expect `kubectl apply -k deploy/kubernetes` to work.
