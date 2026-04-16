# Identity Lifecycle & Access Management Service

> Archetype ID: `identity-lifecycle` | Schema Version: 1.0

## Component Characteristics

Services that manage user accounts, access grants, credential resets, and privileged operations. High blast radius if compromised because identity is the foundation of all authorization decisions.

**Defining traits:**
- Manages creation, modification, and deletion of user identities
- Handles credential operations (password reset, MFA enrollment, token issuance)
- Often integrates with Entra ID / Azure AD via Microsoft Graph
- May expose through Teams bots, portals, or APIs
- Errors can cause organization-wide access disruption

## Review Questions

1. **Privilege escalation:** Can a user with self-service access elevate their own permissions? Can account creation/modification bypass approval workflows?
2. **Credential reset security:** What identity verification is required before credential reset? Can social engineering bypass the verification?
3. **Blast radius:** If this service is compromised, how many users/systems are affected? Is there a break-glass mechanism independent of this service?
4. **Graph API permissions:** What Microsoft Graph permissions does the service use? Are they application-level or delegated? Is the scope minimized?
5. **Token security:** How are issued tokens scoped? Can tokens be replayed across different services or environments?
6. **Audit trail:** Are all identity lifecycle operations (create, modify, delete, grant, revoke) logged with immutable audit trail?
7. **Bot/automation trust:** If operations are triggered via Teams bot or automation, how is the requesting user authenticated and authorized?

## Common Threat Patterns

| Threat Pattern | STRIDE Category | Frequency | Typical Severity |
|---|---|---|---|
| Self-service privilege escalation through permission management API | Elevation of Privilege | High | Critical |
| Social engineering of credential reset process | Spoofing | High | Critical |
| Overly broad Graph API permissions enabling cross-tenant operations | Elevation of Privilege | Medium | Critical |
| Token scope confusion allowing cross-service impersonation | Spoofing | Medium | High |
| Bot command injection triggering unauthorized identity operations | Tampering | Medium | High |
| Missing audit for bulk identity operations | Repudiation | Medium | High |
| Break-glass bypass creating shadow admin accounts | Elevation of Privilege | Low | Critical |

## Decision Patterns

| Decision Area | Common Resolution | Rationale |
|---|---|---|
| Graph API scope | Use delegated permissions over application permissions where possible; scope to minimum required resources | Application permissions bypass user consent and have broader blast radius |
| Credential reset verification | Multi-factor verification required; manager approval for privileged accounts; out-of-band confirmation | Single-factor verification has been bypassed through social engineering |
| Bot command authorization | Verify caller identity through Teams SSO; require explicit confirmation for destructive operations | Bot channel provides different trust level than direct API call |
| Audit requirements | Immutable audit log separate from service database; retain for compliance period (minimum 90 days) | Service-internal logs can be modified by compromised service |
| Least privilege design | Role-based access with separate roles for read, write, and admin operations; no combined "power user" role | Combined roles lead to accidental privilege accumulation |

## Acceptable Risk Patterns

| Risk Condition | Acceptance Criteria | Typical Mitigating Controls |
|---|---|---|
| Application-level Graph permissions for background sync operations | Limited to specific resource types; reviewed quarterly; alerting on permission use outside expected patterns | Scope limiting; usage monitoring; quarterly access review |
| Self-service group membership for non-privileged groups | Groups do not grant access to sensitive resources; membership changes logged | Group classification system; automatic review for groups with sensitive access |
| Bot allows read operations without MFA step-up | Read operations return only non-sensitive information; user identity verified via Teams SSO | Sensitive operations require MFA; read scope limited to user's own data |

## Common Action Items

- [ ] Review and minimize Microsoft Graph API permissions (prefer delegated over application)
- [ ] Implement multi-factor verification for all credential reset operations
- [ ] Add manager approval workflow for privileged account modifications
- [ ] Ensure immutable audit logging for all identity lifecycle operations
- [ ] Implement bot command confirmation for destructive operations
