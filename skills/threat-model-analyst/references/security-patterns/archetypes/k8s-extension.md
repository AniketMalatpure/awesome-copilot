# Kubernetes / Container Orchestration Extension

> Archetype ID: `k8s-extension` | Schema Version: 1.0

## Component Characteristics

Operators, controllers, or extensions deployed into customer-managed Kubernetes clusters, often via Arc or Helm. These components run with varying privilege levels inside clusters the service team does not fully control.

**Defining traits:**
- Deployed into customer-managed Kubernetes clusters
- Often installed as Arc extensions or Helm charts
- Requires Kubernetes RBAC permissions (sometimes cluster-admin)
- Runs alongside customer workloads in shared infrastructure
- Must handle hostile co-tenants (noisy neighbor, pod escape)

## Review Questions

1. **RBAC scope:** Does the extension require cluster-wide permissions or can it be scoped to a specific namespace? What is the minimum RBAC needed?
2. **Pod security posture:** Does the extension require privileged containers, host network, or host PID namespace? Can it function with restricted pod security standards?
3. **Secrets management:** How does the extension access secrets? Are secrets mounted as volumes, environment variables, or accessed via external secret store?
4. **Network isolation:** Does the extension enforce network policies? Can it communicate with pods outside its namespace? Is egress restricted?
5. **Cluster takeover risk:** If the extension's service account is compromised, what is the blast radius? Can it create/modify arbitrary resources cluster-wide?
6. **Upgrade path:** How are extension updates delivered? Can a customer be forced onto a broken version? Is there rollback capability?
7. **Multi-tenancy:** If the extension serves multiple tenants within one cluster, how is tenant data isolated?

## Common Threat Patterns

| Threat Pattern | STRIDE Category | Frequency | Typical Severity |
|---|---|---|---|
| Overly broad RBAC permissions enabling cluster-wide resource manipulation | Elevation of Privilege | High | Critical |
| Pod escape from extension container to host node | Elevation of Privilege | Medium | Critical |
| Secrets exposed via environment variables or unsecured volume mounts | Information Disclosure | High | High |
| Network policy gaps allowing cross-namespace communication | Information Disclosure | Medium | High |
| Compromised service account used to impersonate workloads | Spoofing | Medium | High |
| Extension used as pivot point for lateral movement within cluster | Elevation of Privilege | Medium | Critical |
| Noisy neighbor resource exhaustion affecting extension availability | Denial of Service | Medium | Medium |

## Decision Patterns

| Decision Area | Common Resolution | Rationale |
|---|---|---|
| RBAC scope | Namespace-scoped by default; cluster-wide only with explicit customer opt-in and documented justification | Cluster-admin extensions have been used as pivot points in real incidents |
| Pod security | Restricted pod security standards; no privileged containers unless absolutely required with documented exception | Privileged pods are the primary container escape vector |
| Secret access | Use external secret stores (Azure Key Vault via CSI driver) over in-cluster secrets | In-cluster secrets are accessible to anyone with namespace read access |
| Network policy | Default-deny egress; explicit allowlist for required endpoints | Unrestricted egress enables data exfiltration from compromised pods |
| Update strategy | Canary rollout with automatic rollback on health check failure | Forced updates have caused cluster-wide outages |

## Acceptable Risk Patterns

| Risk Condition | Acceptance Criteria | Typical Mitigating Controls |
|---|---|---|
| Extension requires host network for certain monitoring functions | Specific feature flag enables it; disabled by default; documented risk | Network monitoring limited to read-only operations; no write access to host |
| Cluster-wide RBAC for CRD management | CRDs are read-only for extension; write access only to own namespace resources | Audit logging of all CRD operations; RBAC review on each release |
| Extension runs with higher CPU/memory limits than typical pods | Required for processing workload; resource quotas enforced | Resource quota enforcement; monitoring for anomalous consumption |

## Common Action Items

- [ ] Reduce RBAC permissions to minimum required; document justification for each permission
- [ ] Implement network policies restricting extension egress to known endpoints
- [ ] Migrate secrets from in-cluster Kubernetes secrets to external secret store
- [ ] Add pod security standards compliance; remove privileged container requirements
- [ ] Implement health-check-based rollback for extension updates
