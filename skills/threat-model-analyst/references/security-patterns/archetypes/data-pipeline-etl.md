# Data Pipeline / ETL Service

> Archetype ID: `data-pipeline-etl` | Schema Version: 1.0

## Component Characteristics

Systems that ingest data from multiple sources, transform/aggregate, and make it available for consumption. A key risk is security context downgrade — where data authorized for specific use cases becomes available in broader contexts after aggregation.

**Defining traits:**
- Ingests data from multiple upstream sources with potentially different authorization contexts
- Transforms, aggregates, or joins data, potentially mixing sensitivity levels
- Outputs to downstream consumers who may have different access scopes
- May use protocol-level transports (UDP, custom wire formats) for performance
- Cross-cloud or sovereign data transfers create additional trust boundaries

## Review Questions

1. **Security context preservation:** When data from multiple sources is aggregated, is the original authorization context preserved? Can a downstream consumer access data they shouldn't via the aggregated view?
2. **Data integrity verification:** Is there end-to-end integrity verification from source to destination? Can data be tampered with in transit or at rest within the pipeline?
3. **Payload signing:** Are pipeline messages/payloads signed? Can an attacker inject or modify data mid-pipeline?
4. **Cross-cloud trust:** If data crosses cloud boundaries (public to sovereign), how is trust established? Is there a shared CA or mutual attestation?
5. **ID/reference guessing:** Can an attacker enumerate or guess payload/transfer IDs to access data belonging to other tenants?
6. **Quarantine and staging:** If the pipeline has staging/quarantine buffers, are they protected with the same access controls as the final destination?
7. **Protocol security:** For custom protocols (UDP, proprietary encodings), what are the integrity and confidentiality guarantees? Is there replay protection?

## Common Threat Patterns

| Threat Pattern | STRIDE Category | Frequency | Typical Severity |
|---|---|---|---|
| Security context downgrade through data aggregation (mixed authorization contexts) | Elevation of Privilege | High | High |
| Unsigned pipeline messages enabling data injection or modification | Tampering | High | Critical |
| UDP/custom protocol spoofing in cross-network transfers | Spoofing | Medium | High |
| Payload ID enumeration/guessing enabling cross-tenant data access | Information Disclosure | Medium | High |
| Missing end-to-end integrity verification allowing tampering between pipeline stages | Tampering | Medium | High |
| Quarantine buffer accessible without authorization controls | Information Disclosure | Medium | Medium |
| Cross-cloud trust gap (no shared CA between disconnected environments) | Spoofing | Medium | High |

## Decision Patterns

| Decision Area | Common Resolution | Rationale |
|---|---|---|
| Message signing | Implement signature-based content verification for all pipeline payloads | Unsigned messages in pipelines have been tampered with during transit |
| Protocol security | Prefer TLS for control plane; add application-level integrity for UDP data plane | UDP transport lacks built-in integrity; network-level encryption alone is insufficient |
| Quarantine protection | Keep quarantine data in service-owned storage (not customer storage); apply same access controls | Customer-side quarantine can be accessed by customer before security validation |
| ID generation | Use cryptographically random identifiers; never sequential or guessable | Sequential IDs have been exploited for cross-tenant data enumeration |
| Cross-cloud trust | Manual verification initially; work toward mutual attestation framework | Automated cross-cloud CA trust is an unsolved problem for most sovereign scenarios |

## Acceptable Risk Patterns

| Risk Condition | Acceptance Criteria | Typical Mitigating Controls |
|---|---|---|
| UDP payloads without application-level signing | ExpressRoute isolation provides network-level protection; signing planned | Network isolation; monitoring for anomalous traffic patterns; signing on roadmap |
| No shared CA between public and sovereign clouds | Manual verification acceptable for initial deployment; automation planned | Manifest-based verification; human review of transfers; audit trail |
| Deep review of specific sub-component deferred | Separate security review planned; main system review complete | Tracked work item; risk accepted as time-bound with committed review date |

## Common Action Items

- [ ] Implement payload signing for all pipeline messages (not just control plane)
- [ ] Add end-to-end integrity verification from source through pipeline to destination
- [ ] Use cryptographically random IDs for all payload/transfer identifiers
- [ ] Ensure quarantine/staging buffers have equivalent access controls to final destinations
- [ ] Plan mutual attestation framework for cross-cloud data transfers
