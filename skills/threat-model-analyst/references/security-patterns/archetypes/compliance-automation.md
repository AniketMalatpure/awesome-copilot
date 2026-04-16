# Compliance & Policy Automation Service

> Archetype ID: `compliance-automation` | Schema Version: 1.0

## Component Characteristics

Systems that automate compliance checks, audit validation, regulatory evidence collection, and policy enforcement. These services must be trustworthy themselves while evaluating the trustworthiness of other systems.

**Defining traits:**
- Evaluates other systems against compliance policies and regulatory standards
- Collects and stores evidence/attestation data
- Often requires broad read access across the organization to perform assessments
- Results have business and regulatory consequences (audit findings, compliance reports)
- May use AI/LLM for compliance interpretation or evidence analysis

## Review Questions

1. **Evaluator trust:** How is the compliance evaluation service itself secured? If compromised, can it issue false compliance attestations?
2. **Read access scope:** How broad is the service's read access? Can it be scoped to only the resources being evaluated, or does it require organization-wide reader permissions?
3. **Evidence integrity:** How is collected evidence protected from tampering? Is there an integrity chain from collection to storage to reporting?
4. **False compliance risk:** Can the service be manipulated to report a non-compliant resource as compliant (either through data manipulation or evaluation logic bypass)?
5. **AI-assisted evaluation:** If AI/LLM is used for compliance interpretation, how are hallucinations prevented? Is there a deterministic fallback for critical compliance decisions?
6. **Cross-tenant evidence isolation:** If the service evaluates multiple tenants, is evidence strictly isolated? Can one tenant's compliance data leak to another?
7. **Regulatory data handling:** Does the evidence data itself have regulatory requirements (data residency, retention, access controls)?

## Common Threat Patterns

| Threat Pattern | STRIDE Category | Frequency | Typical Severity |
|---|---|---|---|
| False compliance attestation through evaluation logic manipulation | Tampering | Medium | Critical |
| Over-broad read access creating reconnaissance opportunity | Information Disclosure | High | High |
| Evidence tampering between collection and storage | Tampering | Medium | High |
| AI hallucination in compliance interpretation leading to incorrect assessment | Tampering | Medium | High |
| Cross-tenant evidence leakage in multi-tenant evaluation | Information Disclosure | Medium | High |
| Supply chain attack on validation packages (unsigned CUE/OPA policies) | Tampering | Medium | Critical |
| Telemetry poisoning through unauthenticated instrumentation endpoints | Tampering | Medium | Medium |

## Decision Patterns

| Decision Area | Common Resolution | Rationale |
|---|---|---|
| Validation package integrity | Sign all policy packages (CUE, OPA, custom); reject unsigned or outdated policies | Unsigned policy packages can be replaced with permissive versions |
| AI guardrails | Use AI for assistance/summarization, not for authoritative compliance decisions; human review required for final attestation | AI hallucinations in compliance have direct regulatory consequences |
| Tenant placement | Follow latest guidance for production services; avoid Corp tenant for production workloads | Corp tenant identity isolation may not meet compliance service requirements |
| Evidence storage | Immutable storage with integrity hashing; separate from service operational data | Co-located evidence is vulnerable to same compromises as the service |
| Human approval gates | Do not auto-apply evaluation results; require human review for compliance status changes | Automated compliance changes without review have caused false attestations |

## Acceptable Risk Patterns

| Risk Condition | Acceptance Criteria | Typical Mitigating Controls |
|---|---|---|
| Corp tenant deployment during pilot/preview phase | Time-bound; no production compliance data; migration plan committed | Limited scope; no regulatory reporting from pilot; tracked migration timeline |
| AI-generated compliance summaries without full deterministic verification | Summaries are advisory; final compliance determination is human-reviewed | Clear labeling of AI-generated content; human approval gate before publication |
| Broad reader permissions for compliance scanning | Reader-only access; no write or delete capabilities; scoped to specific management groups | Access review on regular cadence; activity monitoring; least privilege |

## Common Action Items

- [ ] Implement signing and verification for all validation/policy packages
- [ ] Add integrity hashing for evidence from collection through storage
- [ ] Establish human approval gates for compliance status changes (no auto-apply)
- [ ] Authenticate telemetry/instrumentation endpoints (no unauthenticated ingestion)
- [ ] Review and minimize read access scope for compliance scanning
- [ ] Ensure AI-generated content is clearly labeled and requires human review
