# Cloud / Network Infrastructure Management Service

> Archetype ID: `infra-mgmt` | Schema Version: 1.0

## Component Characteristics

Services that provision, configure, and manage cloud or on-prem infrastructure resources (VMs, networking, storage). These operate as Azure Resource Providers or similar infrastructure management layers with broad access to customer resources.

**Defining traits:**
- Manages infrastructure lifecycle (create, update, delete) on behalf of customers
- Often registered as ARM Resource Providers or operates against Fabric Controller
- Multi-tenant with subscription-level scoping
- Managed Identity used for service-to-service communication
- Changes affect running infrastructure — errors have immediate operational impact

## Review Questions

1. **Resource isolation:** How does the service ensure operations on one customer's resources cannot affect another's? Is tenant scoping enforced at every layer?
2. **Managed Identity scope:** What can the service's managed identity access? If compromised, what is the blast radius across subscriptions and tenants?
3. **ARM integration security:** How does the service handle ARM tokens and OBO (on-behalf-of) flows? Are token audience and scope validated at every hop?
4. **Tenant placement:** Is the service deployed in the correct tenant (AME vs Corp vs PME)? Does tenant placement follow latest guidance for the security boundary?
5. **Private networking:** Are management plane endpoints exposed publicly or restricted via Private Link/Service Tags? Can the management API be reached from the internet?
6. **MI certificate lifecycle:** How are managed identity certificates rotated? Is there a gap between certificate expiry and rotation that could cause outages or security exposure?
7. **Customer misconfiguration handling:** How does the service handle cases where customers misconfigure RBAC or networking? Does it fail safely with informative errors?

## Common Threat Patterns

| Threat Pattern | STRIDE Category | Frequency | Typical Severity |
|---|---|---|---|
| Managed Identity over-privilege enabling cross-subscription resource access | Elevation of Privilege | High | Critical |
| ARM OBO token audience confusion across environments | Spoofing | Medium | High |
| Network exposure of management endpoints beyond intended scope | Information Disclosure | Medium | High |
| MI certificate expiry creating authentication gaps | Denial of Service | Medium | Medium |
| Incorrect tenant placement weakening identity isolation | Elevation of Privilege | Medium | High |
| Customer RBAC misconfiguration leading to silent compliance failures | Information Disclosure | Medium | Medium |
| Resource operation side effects affecting co-tenant infrastructure | Denial of Service | Low | High |

## Decision Patterns

| Decision Area | Common Resolution | Rationale |
|---|---|---|
| MI scoping | System-assigned MI per deployment unit; avoid shared MI across services | Shared MI creates blast radius amplification on compromise |
| Network exposure | Private AKS clusters; Private Link for data stores (Cosmos, Storage, Key Vault); RPAS service tags | Public endpoints have been probed and exploited in resource provider services |
| Tenant placement | Follow latest organizational guidance (typically AME for production, not Corp) | Corp tenant has broader access patterns that weaken isolation |
| MI cert lifecycle | Store and rotate MI certificates in Key Vault; monitor for approaching expiry | 90-day MI cert lifecycle with ~45-day rotation creates operational risk if unmonitored |
| ARM token validation | Validate audience, scope, and issuer at every service boundary; reject OBO tokens with unexpected claims | Token forwarding without validation has been a real escalation vector |

## Acceptable Risk Patterns

| Risk Condition | Acceptance Criteria | Typical Mitigating Controls |
|---|---|---|
| Customer misconfiguration causing compliance job failures | Errors surfaced to customer via API response; not a service security issue | Clear error messages with remediation guidance; documentation |
| Temporary Corp tenant placement during pilot phase | Time-bound with committed migration date; pilot scope limited | Migration plan tracked; no production customer data in pilot |
| Public management endpoint for ARM registration | ARM requirement; endpoint protected by ARM authentication and authorization | ARM RBAC enforcement; rate limiting; monitoring for anomalous access |

## Common Action Items

- [ ] Implement system-assigned MI per deployment unit; eliminate shared identities
- [ ] Enable Private Link for all data stores (Cosmos DB, Storage, Key Vault)
- [ ] Set up MI certificate rotation monitoring with alerting before expiry
- [ ] Validate ARM token audience and scope at every service boundary
- [ ] Review and migrate tenant placement per latest organizational guidance
