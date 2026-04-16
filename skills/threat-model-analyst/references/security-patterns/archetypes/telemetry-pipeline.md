# Telemetry / Monitoring Pipeline

> Archetype ID: `telemetry-pipeline` | Schema Version: 1.0

## Component Characteristics

Telemetry pipelines ingest, process, and route metrics, logs, and traces from hosts, containers, and applications at high throughput. They typically involve agents running on customer machines that collect data and forward to cloud-hosted backends.

**Defining traits:**
- High-throughput data ingestion from diverse sources
- Agent-based collection on customer infrastructure
- Configuration-driven behavior (data collection rules, feature flags)
- Often handles sensitive operational data (can contain PII, secrets in logs)

## Review Questions

1. **Config injection:** Can an attacker modify collection rules to exfiltrate data to an external endpoint or expand collection scope beyond intended targets?
2. **Data classification:** Is there automatic PII detection/scrubbing in the pipeline? What happens when secrets appear in log output?
3. **Agent trust model:** How does the collection agent authenticate to the backend? Can a rogue agent impersonate a legitimate one?
4. **Lateral movement via agent:** If the collection agent is compromised, what is the blast radius on the host machine? Does it run with elevated privileges?
5. **Pipeline poisoning:** Can a malicious data source inject crafted telemetry that causes downstream processing failures or data corruption?
6. **Config delivery authentication:** Are configuration updates to agents authenticated and integrity-verified?
7. **Data retention and access control:** Who can query the collected data? Is RBAC enforced at the workspace/scope level?

## Common Threat Patterns

| Threat Pattern | STRIDE Category | Frequency | Typical Severity |
|---|---|---|---|
| Configuration injection redirecting telemetry to attacker-controlled endpoint | Tampering | High | Critical |
| PII/secrets leaking through unfiltered log collection | Information Disclosure | High | High |
| Compromised agent used for lateral movement on host | Elevation of Privilege | Medium | Critical |
| Rogue agent spoofing legitimate data sources | Spoofing | Medium | High |
| Pipeline poisoning via crafted malformed telemetry data | Denial of Service | Medium | Medium |
| Unsigned config updates allowing behavior modification | Tampering | Medium | High |
| Overly broad collection rules capturing sensitive application data | Information Disclosure | High | Medium |

## Decision Patterns

| Decision Area | Common Resolution | Rationale |
|---|---|---|
| Agent privilege level | Run agent with minimum required privileges; use capability-based permissions not root/SYSTEM | Compromised high-privilege agents have led to full host takeover |
| Config delivery integrity | Sign configuration packages; agents reject unsigned or outdated configs | Unsigned config has been exploited for data exfiltration redirection |
| PII handling | Implement scrubbing at the agent level before data leaves the host | Post-ingestion scrubbing is unreliable and creates compliance exposure |
| Agent authentication | Use host-bound certificates or managed identity; rotate regularly | Shared keys across agents create single-point-of-compromise |
| Collection scope controls | Default-deny collection; explicit allowlists for data types/namespaces | Default-allow has led to accidental sensitive data ingestion |

## Acceptable Risk Patterns

| Risk Condition | Acceptance Criteria | Typical Mitigating Controls |
|---|---|---|
| Agent runs with elevated privileges on host | Required for accessing certain system-level telemetry; time-bound plan to reduce | Audit logging of all agent operations; integrity monitoring of agent binary |
| PII may transit pipeline before scrubbing | Scrubbing applied at ingestion point; data at rest is scrubbed; transit is TLS-encrypted | Short retention for raw data; automated PII scan on stored data |
| Legacy agents without certificate-based auth | Deprecation plan with migration timeline; monitoring for suspicious agent registrations | Network isolation + anomaly detection on agent traffic patterns |

## Common Action Items

- [ ] Implement automated PII detection and scrubbing at the agent level
- [ ] Add integrity verification (signing) for configuration delivery to agents
- [ ] Review agent privilege model and reduce to minimum required
- [ ] Implement anomaly detection for collection rule changes (unexpected scope expansion)
- [ ] Add rate limiting and validation on the ingestion endpoint to prevent pipeline poisoning
