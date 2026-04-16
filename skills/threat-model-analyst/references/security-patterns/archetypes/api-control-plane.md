# API Control Plane Service

> Archetype ID: `api-control-plane` | Schema Version: 1.0

## Component Characteristics

API control plane services sit between user-initiated operations and backend services. They manage resources, route requests, enforce authorization, and handle multi-tenant isolation. Typical deployment is cloud-hosted, multi-region, with per-tenant configuration.

**Defining traits:**
- Accepts external HTTP/REST requests and routes to internal backends
- Enforces per-tenant or per-subscription authorization boundaries
- Manages quota, throttling, and resource lifecycle
- Often fronted by Azure Front Door, APIM, or similar gateway

## Review Questions

These questions should be surfaced when a component matches this archetype:

1. **Tenant isolation:** How does the service ensure one tenant cannot access or mutate another tenant's resources? Is isolation enforced at the data layer, not just the API layer?
2. **Token validation:** Where are bearer tokens validated? Is validation performed at the edge or at each hop? Are token replay attacks mitigated (e.g., nonce, audience binding)?
3. **Rate limiting & DoS:** Is rate limiting applied per-tenant, per-IP, or both? What happens when limits are exceeded — graceful degradation or hard failure?
4. **Input validation:** Are all user-supplied resource names, IDs, and query parameters validated against injection and path traversal? Is there a schema-first contract?
5. **Authorization granularity:** Is authorization checked at the operation level (e.g., RBAC on specific resources) or only at the API level? Can a user escalate from read to write via API parameter manipulation?
6. **Error handling & information disclosure:** Do error responses leak internal state, stack traces, or backend topology?
7. **Subscription/scope boundary:** Can a caller cross subscription or management-group boundaries through crafted resource IDs?

## Common Threat Patterns

| Threat Pattern | STRIDE Category | Frequency | Typical Severity |
|---|---|---|---|
| Tenant boundary bypass via crafted resource identifier | Elevation of Privilege | High | Critical |
| Token replay or audience confusion across environments | Spoofing | High | High |
| Rate limit bypass through distributed request patterns | Denial of Service | Medium | Medium |
| Authorization check gap between API gateway and backend | Elevation of Privilege | High | High |
| Information disclosure through verbose error responses | Information Disclosure | Medium | Medium |
| Cross-subscription resource access via scope manipulation | Elevation of Privilege | Medium | Critical |
| Insufficient input validation leading to injection in backend queries | Tampering | Medium | High |
| Admin API exposed without additional authentication factor | Elevation of Privilege | Medium | High |

## Decision Patterns

Patterns observed in how teams resolve these threats:

| Decision Area | Common Resolution | Rationale |
|---|---|---|
| Tenant isolation enforcement | Enforce at data layer (row-level or partition key), not just API middleware | API-layer checks alone have been bypassed through parameter manipulation |
| Token validation location | Validate at both edge gateway AND service layer; never trust gateway-only validation | Gateway bypass via direct-to-backend calls has occurred in practice |
| Rate limiting strategy | Per-tenant + per-IP compound limits; use token bucket not fixed window | Fixed-window limits are trivially gameable at boundary |
| Admin API protection | Require separate authentication flow (e.g., JIT, MFA step-up) for admin operations | Same-token admin access leads to lateral movement |
| Resource ID validation | Strict regex on all resource identifiers; reject anything not matching expected format | Overly permissive ID parsing is a common entry point for scope escapes |

## Acceptable Risk Patterns

Conditions under which certain risks have been accepted in similar systems:

| Risk Condition | Acceptance Criteria | Typical Mitigating Controls |
|---|---|---|
| Rate limiting not fully enforced on internal-only APIs | Internal APIs are only reachable from trusted VNet; no public exposure | VNet isolation + NSG rules + monitoring for anomalous internal traffic |
| Verbose error messages in development/staging environments | Errors are stripped in production; staging has no real tenant data | Environment parity checks in deployment pipeline |
| Legacy API versions without latest auth model | Time-bound deprecation plan with monitoring for usage; sunset date committed | Usage telemetry + deprecation headers + customer notification |

## Common Action Items

Typical remediation actions assigned during reviews of this archetype:

- [ ] Implement end-to-end tenant isolation tests (not just unit tests — integration tests crossing API to data layer)
- [ ] Add authorization regression test suite covering scope escalation scenarios
- [ ] Enable request tracing with correlation IDs for cross-service calls
- [ ] Audit all error responses for information leakage; implement structured error envelope
- [ ] Document rate-limiting behavior per API tier in customer-facing documentation
