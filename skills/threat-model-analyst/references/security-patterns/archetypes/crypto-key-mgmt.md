# Cryptographic / Key Management Service

> Archetype ID: `crypto-key-mgmt` | Schema Version: 1.0

## Component Characteristics

Services that generate, store, rotate, and manage cryptographic keys, certificates, and signing operations. These are high-value targets because compromising key material can cascade to all systems relying on those keys.

**Defining traits:**
- Manages cryptographic material (keys, certificates, secrets)
- Often backed by HSMs or secure enclaves
- Supports rotation, revocation, and lifecycle management
- High blast radius — compromise affects all dependent systems

## Review Questions

1. **Key material exposure:** Is key material ever exposed in plaintext outside the HSM/secure boundary? Does the service API return raw keys or only references/handles?
2. **Access control granularity:** Can callers be restricted to specific operations (sign vs. decrypt) on specific keys? Is RBAC per-key or per-vault?
3. **Rotation strategy:** Is key rotation automated? What is the process for emergency rotation if a key is suspected compromised?
4. **Audit completeness:** Are all key operations (create, use, rotate, delete) logged with caller identity? Are logs tamper-resistant?
5. **Insider threat:** What prevents a service operator from extracting or using key material outside normal operations?
6. **Build-time secrets:** Are signing keys used in build pipelines protected from pipeline compromise (e.g., isolated signing service)?
7. **Certificate chain validation:** Does the service validate the full certificate chain, or does it trust leaf certificates alone?

## Common Threat Patterns

| Threat Pattern | STRIDE Category | Frequency | Typical Severity |
|---|---|---|---|
| Key material exposed through API response or logging | Information Disclosure | High | Critical |
| Insufficient access control allowing unauthorized signing operations | Elevation of Privilege | High | Critical |
| Missing or incomplete key rotation leading to long-lived compromised material | Tampering | Medium | High |
| Insider abuse of key management privileges | Elevation of Privilege | Medium | Critical |
| Build pipeline compromise leading to unauthorized artifact signing | Tampering | Medium | Critical |
| Audit log gaps allowing undetected key usage | Repudiation | Medium | High |
| Weak certificate chain validation enabling impersonation | Spoofing | Medium | High |

## Decision Patterns

| Decision Area | Common Resolution | Rationale |
|---|---|---|
| Key storage boundary | HSM-backed storage for all production signing keys; software keys only for non-production | Software key extraction has been demonstrated in multiple attack scenarios |
| API design for key access | Return key references (URIs/handles), never raw material; signing performed server-side | Client-side signing requires key material transit, which is the primary risk vector |
| Rotation automation | Automated rotation with zero-downtime dual-key overlap period | Manual rotation creates windows of vulnerability and operational risk |
| Audit requirements | Immutable audit log for all key operations; separate from service logs | Co-located logs can be tampered with by operators with service access |
| Separation of duties | Key creation and key usage require different identities/roles | Single-identity key management is the most common insider threat vector |

## Acceptable Risk Patterns

| Risk Condition | Acceptance Criteria | Typical Mitigating Controls |
|---|---|---|
| Software-backed keys for non-sensitive operations | Non-production, non-signing use cases only; reviewed quarterly | Monitoring for any production traffic using software keys |
| Manual rotation for legacy certificate authorities | Migration to automated rotation in progress; 90-day rotation cycle maintained | Calendar-driven rotation reminders; alerting on approaching expiry |
| Operator access to key vault for break-glass scenarios | Requires dual approval; all access logged and reviewed within 24 hours | PIM-based JIT access with mandatory justification and audit |

## Common Action Items

- [ ] Migrate all production signing keys to HSM-backed storage
- [ ] Implement automated key rotation with zero-downtime dual-key overlap
- [ ] Add separation of duties between key creation and key usage roles
- [ ] Ensure all key operations are logged in tamper-resistant audit system
- [ ] Review API surface for any endpoint that returns raw key material
