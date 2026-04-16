# Edge / On-Prem Appliance

> Archetype ID: `edge-appliance` | Schema Version: 1.0

## Component Characteristics

Software running on customer-controlled hardware or edge infrastructure, often with limited or intermittent cloud connectivity. The customer (or a local admin) has physical access to the device, creating a fundamentally different trust model than cloud services.

**Defining traits:**
- Runs on hardware the service team does not control
- Must function in disconnected/air-gapped scenarios
- Local admin has significant privileges on the device
- Update and diagnostic mechanisms must work offline or semi-offline
- Physical access by potentially untrusted actors

## Review Questions

1. **Trust boundary at the device:** Given that local admins have physical access, what is the trust model? What can a malicious local admin achieve?
2. **Offline authentication:** How does the device authenticate users and services when cloud connectivity is unavailable? Is there a cached credential mechanism, and how is it protected?
3. **Update integrity:** How are software updates delivered and verified? Can an attacker with network position inject a malicious update package?
4. **Diagnostic data exfiltration:** What data is collected in diagnostic bundles? Could support bundles contain secrets, keys, or customer data?
5. **Local secret storage:** How are secrets (certificates, keys, passwords) stored on the device? Is there TPM/HSM backing or software-only protection?
6. **Network exposure:** What ports and services are exposed on the local network? Is the management interface accessible from untrusted network segments?
7. **Recovery and factory reset:** What happens during device recovery? Can the reset process be abused to bypass security controls?

## Common Threat Patterns

| Threat Pattern | STRIDE Category | Frequency | Typical Severity |
|---|---|---|---|
| Privilege escalation from local admin to service operator | Elevation of Privilege | High | Critical |
| Malicious update package injection via untrusted network | Tampering | High | Critical |
| Secret extraction from device storage (no HSM protection) | Information Disclosure | High | Critical |
| Diagnostic bundle containing sensitive data sent to untrusted destination | Information Disclosure | Medium | High |
| Offline credential cache abuse after employee departure | Spoofing | Medium | High |
| Untrusted input processing from locally-supplied files (ZIP, config) | Tampering | High | High |
| Management interface exposed on untrusted network segment | Elevation of Privilege | Medium | High |
| Physical tampering or component replacement | Tampering | Low | Critical |

## Decision Patterns

| Decision Area | Common Resolution | Rationale |
|---|---|---|
| Local admin trust level | Treat local admin as semi-trusted; limit access to service-level secrets and operations | Full trust of local admin has led to service-level credential extraction |
| Update verification | Code-sign all update packages; verify signature before extraction; reject unsigned payloads | Network-based update injection is a high-frequency attack vector for edge devices |
| Secret storage | Use TPM-bound storage where available; fall back to DPAPI with additional access controls | Software-only secret storage is extractable by local admin |
| Diagnostic data | Automated scrubbing of secrets/PII before bundle creation; customer review before upload | Support bundles have historically contained extractable credentials |
| Offline authentication | Time-limited cached tokens with device-bound encryption; force re-auth on cloud reconnect | Unbounded cached credentials persist after access should be revoked |

## Acceptable Risk Patterns

| Risk Condition | Acceptance Criteria | Typical Mitigating Controls |
|---|---|---|
| Local admin can read certain configuration data | Config data does not include secrets or service credentials; secrets are in separate protected store | Separation of config and secrets; audit logging of config access |
| Device cannot enforce credential revocation while offline | Maximum offline period defined (e.g., 72 hours); device locked after timeout | Offline timeout enforcement; re-authentication required on reconnect |
| Diagnostic bundles may contain hostname/IP information | Information is about customer's own infrastructure; no cross-tenant data | Customer controls upload destination; bundle manifest for review |

## Common Action Items

- [ ] Implement code signing for all update packages with pre-extraction signature verification
- [ ] Migrate local secret storage to TPM-bound mechanism where hardware supports it
- [ ] Add automated secret/PII scrubbing to diagnostic bundle creation process
- [ ] Define and enforce maximum offline authentication window
- [ ] Audit all locally-exposed network services and restrict management interface to dedicated management network
