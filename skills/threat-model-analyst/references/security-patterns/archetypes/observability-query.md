# Observability & Analytics Query Service

> Archetype ID: `observability-query` | Schema Version: 1.0

## Component Characteristics

Services that provide read access to aggregated system data (logs, metrics, traces, diagnostic stacks) for diagnostics and analysis. Though nominally "read-only," these services can expose sensitive operational data and PII.

**Defining traits:**
- Provides query interfaces over aggregated telemetry and operational data
- Data may contain PII, secrets in logs, or security-sensitive operational details
- User-facing analytics dashboards or API endpoints
- Often uses on-behalf-of (OBO) authentication for scoped access
- Data retention policies affect exposure window

## Review Questions

1. **Query scope enforcement:** Is the user's query restricted to resources they have access to? Can a crafted query bypass RBAC to access other tenants' data?
2. **PII in query results:** Does the query service filter PII from results, or is it the responsibility of upstream data ingestion? Can a user query for data containing secrets or credentials?
3. **Data retention exposure:** How long is sensitive data retained? Is there a mechanism to purge data on request (GDPR/compliance)?
4. **Delegation model:** If the service uses OBO tokens, are token scopes properly restricted? Can a delegated token access more data than the original user?
5. **Dashboard access control:** Are saved dashboards/queries access-controlled? Can a shared dashboard expose data to users who shouldn't see it?
6. **API rate limiting:** Is the query API rate-limited to prevent data exfiltration through high-volume queries?
7. **Cross-workspace access:** Can a user query across multiple workspaces or log analytics instances to aggregate data beyond their intended scope?

## Common Threat Patterns

| Threat Pattern | STRIDE Category | Frequency | Typical Severity |
|---|---|---|---|
| PII/credential leakage through log query results | Information Disclosure | High | High |
| Query scope bypass enabling cross-tenant data access | Elevation of Privilege | Medium | Critical |
| Improper OBO token delegation expanding data access beyond user's scope | Elevation of Privilege | Medium | High |
| Shared dashboard exposing restricted data to broader audience | Information Disclosure | Medium | Medium |
| High-volume query exploitation for data exfiltration | Information Disclosure | Medium | High |
| Cross-workspace aggregation bypassing workspace-level RBAC | Elevation of Privilege | Medium | High |
| Stale data retention exposing historical sensitive information | Information Disclosure | Medium | Medium |

## Decision Patterns

| Decision Area | Common Resolution | Rationale |
|---|---|---|
| Query RBAC | Enforce user-level RBAC at query time, not just at workspace level; filter results to user's authorized resources | Workspace-level RBAC alone allows over-broad access within the workspace |
| PII handling | Scrub PII at ingestion (preferred) or apply masking at query time; never return raw log content without filtering | Raw log queries have revealed credentials, tokens, and PII in practice |
| OBO scoping | Validate OBO token scope at each service boundary; never expand scope beyond original user's permissions | OBO scope expansion is a common source of privilege escalation |
| Dashboard sharing | Dashboard sharing inherits viewer's RBAC (server-side evaluation), not creator's permissions | Creator-scoped dashboards cause confused deputy when shared |
| Retention policy | Define and enforce data retention aligned with compliance requirements; automated purge at expiry | Manual purge processes create compliance gaps |

## Acceptable Risk Patterns

| Risk Condition | Acceptance Criteria | Typical Mitigating Controls |
|---|---|---|
| Log data may contain trace-level details including IP addresses | IPs are operational data for the customer's own resources; not cross-tenant | Data restricted to customer's own workspace; access logged |
| Query results include system-generated identifiers (correlation IDs, request IDs) | Identifiers alone are not sensitive; cannot be used for lateral movement | Identifiers are opaque; no secondary lookup APIs exposed |
| Historical data retained beyond minimal period for compliance | Compliance mandates specific retention; deletion on expiry is automated | Access to historical data requires elevated permissions; audit logged |

## Common Action Items

- [ ] Implement query-time RBAC enforcement scoped to user's authorized resources
- [ ] Add PII detection and masking in query result pipeline
- [ ] Validate OBO token scope at every service boundary in the query path
- [ ] Ensure shared dashboards evaluate viewer's permissions, not creator's
- [ ] Define and enforce data retention policies with automated purge
