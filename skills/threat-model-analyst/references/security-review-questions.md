# Security Review Questions Library

> Derived from patterns observed across 147 real threat model review meetings.
> These questions represent what experienced security reviewers consistently ask.
> The agent should map relevant questions to the system under analysis based on component types and trust boundaries.

## How to Use This File

1. **After Step 1 (component identification)**, scan this question library
2. **Match questions** to the system's components by archetype tags (e.g., a system with an API gateway gets all `api-control-plane` questions)
3. **Answer each relevant question** from code evidence where possible
4. **Flag unanswerable questions** with 🔍 for manual team input
5. **Include the mapped Q&A** as a `## Security Review Questions` section in `3-threatmodel.md`, placed **after the DFD diagrams (and Summary View if present) but before the Element Table**

---

## 1. Authentication & Identity

**Applies to:** All systems with network-exposed services, APIs, or multi-component architectures.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| AUTH-01 | How are API endpoints authenticated? Is authentication enforced on all controller actions, or are some open? | `api-control-plane`, `infra-mgmt` |
| AUTH-02 | Will services validate tokens against AAD / Entra ID, or use a custom auth mechanism? | `api-control-plane`, `identity-lifecycle` |
| AUTH-03 | How is the operator/user identity cryptographically bound to a specific session? | `identity-lifecycle`, `api-control-plane` |
| AUTH-04 | How do isolated/sandboxed components authenticate back to control plane services? | `edge-appliance`, `k8s-extension` |
| AUTH-05 | How does the service authenticate to external cloud dependencies (Key Vault, AI endpoints, storage)? Can credentials be stolen from config? | `ai-llm-service`, `infra-mgmt`, `crypto-key-mgmt` |
| AUTH-06 | Is there zero authentication between any internal microservices? If so, what compensating controls exist? | `api-control-plane`, `data-pipeline-etl` |
| AUTH-07 | How does break-glass / emergency access work if primary auth dependencies are down? | `identity-lifecycle`, `infra-mgmt` |
| AUTH-08 | Are non-human identities (service principals, managed identities) scoped with least privilege? | `identity-lifecycle`, `k8s-extension` |
| AUTH-09 | When have users given consent for their data to flow to this service? | `ai-llm-service`, `telemetry-pipeline` |
| AUTH-10 | For tokens issued by an external OAuth IdP, how are claims (audience, issuer, scope, expiry) validated to prevent token confusion attacks across APIs? | `api-control-plane`, `identity-lifecycle` |
| AUTH-11 | How is federation trust established between internal identity providers and external OAuth providers without allowing the external IdP to impersonate internal services? | `identity-lifecycle`, `api-control-plane` |
| AUTH-12 | Can Proof-of-Possession (PoP) tokens replace bearer-only authentication to prevent token replay and lateral movement? | `api-control-plane`, `identity-lifecycle` |
| AUTH-13 | In systems using mTLS between microservices, is there explicit cryptographic binding between the application process and its sidecar proxy, or can a co-located process impersonate a legitimate service? | `api-control-plane`, `k8s-extension` |
| AUTH-14 | Are service-to-service RPC payloads parsed before authentication is validated, creating a pre-auth attack surface? | `api-control-plane`, `data-pipeline-etl` |
| AUTH-15 | Can Managed Identity fully replace certificate-based auth and service principals, and what is the migration timeline? | `identity-lifecycle`, `infra-mgmt` |

## 2. Authorization & Access Control

**Applies to:** All systems with multi-tenant access, role-based features, or admin operations.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| AUTHZ-01 | What RBAC model governs who can register, modify, or delete critical resources (agents, configs, policies)? | `api-control-plane`, `infra-mgmt` |
| AUTHZ-02 | Can any local/network process call privileged control plane endpoints without authorization? | `api-control-plane`, `edge-appliance` |
| AUTHZ-03 | Are capabilities/permissions enforced per-component or per-namespace, not just system-wide? | `k8s-extension`, `api-control-plane` |
| AUTHZ-04 | Can orchestration/deployment permissions be scoped per namespace, tenant, or resource? | `k8s-extension`, `infra-mgmt` |
| AUTHZ-05 | Is there an allowlist of which components are permitted to call sensitive backend services? | `ai-llm-service`, `api-control-plane` |
| AUTHZ-06 | Are customer OBO (on-behalf-of) tokens used end-to-end, or does the system use a shared first-party identity? | `identity-lifecycle`, `k8s-extension` |
| AUTHZ-07 | What exact RBAC permissions does the bridge/proxy component require on downstream systems? | `k8s-extension`, `infra-mgmt` |
| AUTHZ-08 | Should system namespaces or critical paths be explicitly blocked or require elevated approval? | `k8s-extension`, `build-supply-chain` |
| AUTHZ-09 | When the same Managed Identity is used across multiple clusters or services, how is blast radius limited if that identity is compromised? | `identity-lifecycle`, `k8s-extension`, `infra-mgmt` |
| AUTHZ-10 | For services with broad RBAC roles (e.g., "Blob Data Contributor" for logging), are there append-only or write-only alternatives to reduce blast radius? | `infra-mgmt`, `telemetry-pipeline` |
| AUTHZ-11 | When autoscale or orchestration actions are delegated to customer-provided identities, what minimum-privilege guidance exists to prevent over-provisioning? | `infra-mgmt`, `k8s-extension` |
| AUTHZ-12 | For multi-tenant services where workspace creation is user-initiated, are per-user or per-tenant quotas enforced to prevent DoS via resource flooding? | `api-control-plane`, `infra-mgmt` |

## 3. Secrets & Credential Management

**Applies to:** All systems handling API keys, certificates, connection strings, or encryption keys.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| SEC-01 | Are secrets stored in a vault (Key Vault, DPAPI, HSM) or in plaintext config files? | `crypto-key-mgmt`, `all` |
| SEC-02 | How are API keys and credentials rotated? Is there an automated rotation mechanism? | `crypto-key-mgmt`, `api-control-plane` |
| SEC-03 | Are development credentials separated from production credentials? Are dev endpoints checked into source control? | `build-supply-chain`, `all` |
| SEC-04 | How will key generation, rotation, and lifetime be handled for encryption keys? | `crypto-key-mgmt` |
| SEC-05 | How are certificate rotations and revocations propagated? | `crypto-key-mgmt`, `edge-appliance` |
| SEC-06 | Should decryption occur at the edge vs backend to reduce concentration of risk? | `crypto-key-mgmt`, `edge-appliance` |
| SEC-07 | What mechanisms prevent residual sensitive key material from persisting in storage or memory after key rotation or cryptographic boundary changes? | `crypto-key-mgmt`, `edge-appliance` |
| SEC-08 | At hardware manufacturing time, what prevents OEMs or contract manufacturers from retaining copies of private keys used in the boot chain? | `crypto-key-mgmt`, `edge-appliance` |
| SEC-09 | Can key material be explicitly zeroed in memory post-use, especially in memory-unsafe languages (Go, C)? | `crypto-key-mgmt`, `all` |
| SEC-10 | When encryption keys are retained "for legacy compatibility" rather than cryptographic necessity, what triggers re-evaluation and eventual key removal? | `crypto-key-mgmt`, `infra-mgmt` |
| SEC-11 | For secrets encrypted in memory caches (Redis), does defense-in-depth double-encryption sufficiently reduce blast radius? | `crypto-key-mgmt`, `api-control-plane` |
| SEC-12 | Are secrets stored in plaintext in bearer token files or environment variables? What mitigations exist for insider threat scenarios? | `crypto-key-mgmt`, `infra-mgmt` |

## 4. Input Validation & Prompt Injection

**Applies to:** All systems accepting external input, especially those with LLM/AI components.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| INPUT-01 | How is prompt injection mitigated in the LLM request path? Schema-based or heuristic? | `ai-llm-service` |
| INPUT-02 | Are credentials, PII, or sensitive information redacted before passing context to the LLM? | `ai-llm-service` |
| INPUT-03 | Can all user-controlled identifiers be reliably detected and stripped? | `ai-llm-service`, `api-control-plane` |
| INPUT-04 | What input validation exists on API request bodies? Is it consistent across all endpoints? | `api-control-plane`, `all` |
| INPUT-05 | Can LLM outputs include URLs or instructions leading outside the organization? Is output filtering enforced? | `ai-llm-service` |
| INPUT-06 | How is post-processing enforced to guarantee read-only behavior from AI recommendations? | `ai-llm-service` |
| INPUT-07 | What formal guarantees exist around untrusted input sanitization? | `api-control-plane`, `data-pipeline-etl` |
| INPUT-08 | What XML/JSON parsing library is used? Are safe deserializers explicitly validated? | `data-pipeline-etl`, `build-supply-chain` |
| INPUT-09 | What is the maximum safe payload size? Are there size limits on request bodies? | `api-control-plane`, `ai-llm-service` |
| INPUT-10 | Are all custom archive parsers (ZIP, TAR, XZ, RPM, VHD) attached to fuzzers with adequate coverage? | `build-supply-chain`, `data-pipeline-etl` |
| INPUT-11 | Can Zip Slip vulnerabilities be eliminated by using GUID-based filenames instead of trusting archive-provided paths? | `data-pipeline-etl`, `build-supply-chain` |
| INPUT-12 | What compression ratio and recursion depth limits prevent Zip Bomb attacks without blocking legitimate use cases? | `data-pipeline-etl`, `build-supply-chain` |
| INPUT-13 | For services accepting structured config (JSON, XML, protobuf), is fuzz testing enforced in CI/CD before code review? | `api-control-plane`, `data-pipeline-etl` |
| INPUT-14 | When KQL, SQL, or other query languages are constructed from user input or LLM output, are parameterized queries enforced to prevent injection? | `observability-query`, `ai-llm-service`, `data-pipeline-etl` |
| INPUT-15 | Should HTML sanitization be enforced backend-side for all user-supplied justification, policy text, or free-form fields? | `api-control-plane`, `compliance-automation` |

## 5. Network Exposure & Transport Security

**Applies to:** All systems with network listeners, service-to-service communication, or cloud connectivity.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| NET-01 | Which services listen on `0.0.0.0` (all interfaces) vs `localhost` / named pipes? | `api-control-plane`, `edge-appliance` |
| NET-02 | Is HTTPS/TLS enforced for all service-to-service communication, or just external calls? | `api-control-plane`, `all` |
| NET-03 | Is mTLS used between any components? Is certificate pinning feasible? | `api-control-plane`, `edge-appliance` |
| NET-04 | Can network segmentation (NetworkPolicy, Calico, firewall rules) isolate component traffic? | `k8s-extension`, `infra-mgmt` |
| NET-05 | What formal guarantees does the relay/proxy provide against endpoint impersonation? | `api-control-plane`, `edge-appliance` |
| NET-06 | Can UDP/non-TLS flows be hardened without breaking hardware or performance constraints? | `edge-appliance`, `telemetry-pipeline` |
| NET-07 | How to enforce deterministic outbound blocking (egress control) for LLM-calling components? | `ai-llm-service`, `k8s-extension` |
| NET-08 | When cloud services use Azure Front Door or Traffic Manager, can they be accessed from arbitrary internet locations, or are there Service Tag/IP restrictions? | `api-control-plane`, `infra-mgmt` |
| NET-09 | Should internal microservices enforce encryption between all components (even within the same VNET), or is network segmentation alone sufficient? | `api-control-plane`, `k8s-extension` |
| NET-10 | For edge appliances using Private Link or non-routable IPs for activation, how is service discovery validated to prevent DNS spoofing or MITM? | `edge-appliance`, `infra-mgmt` |
| NET-11 | Can UDP/non-TLS flows (e.g., sovereign data transfers) be hardened against packet injection and spoofing without breaking hardware constraints? | `edge-appliance`, `data-pipeline-etl` |
| NET-12 | Should Redis, RabbitMQ, and other middleware enforce TLS in all deployment modes including edge scenarios? | `edge-appliance`, `api-control-plane` |

## 6. Process Isolation & Privilege

**Applies to:** Systems with multi-process architectures, sandboxing, or privilege boundaries.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| ISOL-01 | What is the blast radius if a component is compromised inside its isolation boundary? | `edge-appliance`, `k8s-extension` |
| ISOL-02 | Does the process launcher/manager run with elevated privileges? What is the minimum required? | `infra-mgmt`, `edge-appliance` |
| ISOL-03 | Can a compromised component escape its sandbox/container/AppContainer isolation? | `k8s-extension`, `edge-appliance` |
| ISOL-04 | Does the system execute manifest-supplied commands or paths without trusted provenance enforcement? | `infra-mgmt`, `build-supply-chain` |
| ISOL-05 | Can split-privilege architecture reduce the privileges of high-risk components? | `infra-mgmt`, `edge-appliance` |
| ISOL-06 | If running with cluster-wide permissions, is this an acceptable risk? What is the blast radius? | `k8s-extension` |
| ISOL-07 | Can Kubernetes workload identity be scoped per container instead of cluster-wide? | `k8s-extension`, `infra-mgmt` |
| ISOL-08 | For test execution platforms running user-authored code in shared infrastructure, should isolation use Hyper-V containers, or can pod-level network policies suffice? | `k8s-extension`, `build-supply-chain` |
| ISOL-09 | When edge-originated custom resources can trigger cloud resource creation (e.g., ARM), what prevents an edge compromise from creating resources outside subscription boundaries? | `edge-appliance`, `k8s-extension`, `infra-mgmt` |

## 7. CORS & Cross-Origin Security

**Applies to:** Systems with web APIs accessible from browsers or cross-origin contexts.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| CORS-01 | What is the CORS policy on exposed HTTP APIs? Is `AllowAnyOrigin` used? | `api-control-plane` |
| CORS-02 | Are WebSocket origins strictly enforced? | `api-control-plane`, `observability-query` |
| CORS-03 | Can the API be called from untrusted browser contexts? | `api-control-plane` |

## 8. Telemetry & Data Leakage

**Applies to:** All systems with logging, metrics, tracing, or telemetry pipelines.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| TEL-01 | Does telemetry contain PII or sensitive operational data? Is there PII filtering? | `telemetry-pipeline`, `observability-query` |
| TEL-02 | Is telemetry data encrypted in transit to the collection endpoint? | `telemetry-pipeline` |
| TEL-03 | What is the telemetry retention policy? Is retention minimized per data classification? | `telemetry-pipeline`, `compliance-automation` |
| TEL-04 | Can telemetry be used for compromise detection? Are security-specific signals instrumented? | `telemetry-pipeline`, `observability-query` |
| TEL-05 | Is unauthenticated telemetry ingestion acceptable under SDL/SFI requirements? | `telemetry-pipeline` |
| TEL-06 | Should telemetry from AI calls (prompts, responses) be stored or audited? With what redaction? | `ai-llm-service`, `telemetry-pipeline` |
| TEL-07 | When diagnostic telemetry from on-premises devices is exfiltrated to cloud, what ensures credential/PII redaction occurs before data leaves the device? | `telemetry-pipeline`, `edge-appliance` |
| TEL-08 | For on-device credential redaction, how is the authenticity of the redaction configuration verified? Can a compromised device modify redaction policy? | `telemetry-pipeline`, `edge-appliance` |
| TEL-09 | When process telemetry includes command-line arguments, should secret redaction be automatic, manual, or policy-driven? | `telemetry-pipeline`, `observability-query` |
| TEL-10 | Is access to diagnostics/analytics data containing customer PII restricted to Secure Admin Workstations (SAW) with audit logging of all queries? | `telemetry-pipeline`, `compliance-automation` |
| TEL-11 | How should lower-threshold monitoring detect silent data loss when telemetry parsing fails? | `telemetry-pipeline`, `observability-query` |
| TEL-12 | Are Geneva/collector parsing guarantees sufficient to protect against log injection attacks? | `telemetry-pipeline`, `observability-query` |

## 9. Error Handling & Information Disclosure

**Applies to:** All systems with external-facing APIs or user-visible error messages.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| ERR-01 | Do error responses leak internal implementation details (exception messages, stack traces, internal paths)? | `api-control-plane`, `all` |
| ERR-02 | Is there a global exception handler to catch unhandled errors and return sanitized responses? | `api-control-plane`, `all` |
| ERR-03 | Are error details logged server-side but stripped from client responses? | `api-control-plane` |

## 10. Supply Chain & Manifest Integrity

**Applies to:** Systems that load configurations, manifests, plugins, or external artifacts.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| SC-01 | Are configuration manifests (YAML, JSON, XML) cryptographically signed? Can tampering cause arbitrary execution? | `build-supply-chain`, `infra-mgmt` |
| SC-02 | What pipeline/approval gates exist before new components or plugins are registered? | `build-supply-chain`, `api-control-plane` |
| SC-03 | Are container images, executables, or models verified (hash, signature) before execution? | `build-supply-chain`, `k8s-extension`, `ai-llm-service` |
| SC-04 | What library dependencies are used? Are they from trusted, monitored sources? | `build-supply-chain`, `all` |
| SC-05 | Can universal packages or artifacts be cryptographically signed end-to-end? | `build-supply-chain` |
| SC-06 | What certificate chain signs production artifacts? Are test certs separated from production certs? | `build-supply-chain`, `crypto-key-mgmt` |
| SC-07 | When build artifacts are scanned (e.g., ESRP), how is integrity guaranteed at deployment time? Is there a TOCTOU gap between scan and deploy? | `build-supply-chain`, `infra-mgmt` |
| SC-08 | For high-privilege build identities that bypass approval gates and hold signing certificates, what prevents unauthorized contributors from queuing malicious builds? | `build-supply-chain` |
| SC-09 | Should runtime verification enforce that deployed binaries are cryptographically signed before execution? | `build-supply-chain`, `edge-appliance` |
| SC-10 | For package managers (NuGet, npm, vcpkg), how are compromised upstream feeds detected? Is out-of-band signing sufficient? | `build-supply-chain`, `all` |
| SC-11 | Should proof-of-possession (PoP) tokens replace bearer-only authentication for package feed access? | `build-supply-chain`, `api-control-plane` |
| SC-12 | How are third-party binaries (e.g., via MSI installers) governed for component integrity when regular updates are not controlled by the team? | `build-supply-chain`, `edge-appliance` |

## 11. LLM / AI-Specific Security

**Applies to:** Systems with LLM integration, AI inference, RAG pipelines, or agent orchestration.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| AI-01 | How is cross-tenant or cross-session data leakage prevented when multiple users share an LLM endpoint? | `ai-llm-service` |
| AI-02 | Is the LLM call stateless? Can previous conversations leak into new ones? | `ai-llm-service` |
| AI-03 | How is BYOM (Bring Your Own Model) endpoint trust addressed? Is there model integrity verification? | `ai-llm-service`, `edge-appliance` |
| AI-04 | Is rate limiting enforced on LLM calls to prevent abuse or cost explosion? | `ai-llm-service` |
| AI-05 | Should AI models use CI-style policy enforcement (signed, versioned, tested before deployment)? | `ai-llm-service`, `build-supply-chain` |
| AI-06 | How to cryptographically bind the application to its AI sidecar/service? | `ai-llm-service` |
| AI-07 | What data classifications are safe to expose to the AI service by default? | `ai-llm-service`, `compliance-automation` |
| AI-08 | The internet is forever — if data reaches an AI endpoint, can it be fully wiped? What is the guaranteed wipe procedure? | `ai-llm-service` |
| AI-09 | Are ML models treated with the same security rigor as executable code (CI/CD, signing, versioning, vulnerability scanning)? | `ai-llm-service`, `build-supply-chain` |
| AI-10 | When users bring their own models (BYOM) or external model endpoints, how is model integrity and provenance guaranteed? Can a malicious endpoint be substituted? | `ai-llm-service`, `edge-appliance` |
| AI-11 | Should LLM outputs be treated as advisory-only, or can they trigger limited write operations if carefully scoped? | `ai-llm-service` |
| AI-12 | How is untrusted feedback data (from bug trackers, forums, user reports) sanitized before LLM processing to prevent prompt injection? | `ai-llm-service`, `data-pipeline-etl` |
| AI-13 | Should engineers be treated as adversarial when they can craft inputs to internal AI triage/classification tools? | `ai-llm-service`, `build-supply-chain` |
| AI-14 | Are OpenAI content filters and jailbreak mitigations explicitly enabled and validated for all conversational agent endpoints? | `ai-llm-service` |
| AI-15 | For evaluation pipelines using LLM-generated results, how is metric manipulation or false accuracy reports prevented? | `ai-llm-service`, `data-pipeline-etl` |

## 12. Operational Resilience & Break-Glass

**Applies to:** Production systems where availability and incident response matter.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| OPS-01 | What happens if a critical dependency (catalog, auth, config store) goes down? Can the system degrade gracefully? | `infra-mgmt`, `api-control-plane` |
| OPS-02 | Is there a break-glass mechanism to kill all running agents/workloads in an emergency? | `infra-mgmt`, `k8s-extension` |
| OPS-03 | How is emergency access authenticated, authorized, time-bound, and audited? | `identity-lifecycle`, `compliance-automation` |
| OPS-04 | How is misuse or abuse of emergency/admin paths detected? | `identity-lifecycle`, `observability-query` |
| OPS-05 | Should API key fallback be time-boxed during disconnected/degraded scenarios? | `edge-appliance`, `crypto-key-mgmt` |
| OPS-06 | Are additional hardening or monitoring requirements discovered during pen testing tracked to completion? | `compliance-automation`, `all` |
| OPS-07 | Should services enforce geographic or service-tree-based authorization to prevent over-broad deployment visibility? | `infra-mgmt`, `compliance-automation` |
| OPS-08 | Are audit logs explicitly produced for all security-sensitive admin actions (Key Vault operations, policy deletions, parameter changes)? | `infra-mgmt`, `compliance-automation` |
| OPS-09 | How is misuse of emergency/admin paths detected? Are break-glass account accesses fully audited with rotation practices? | `identity-lifecycle`, `compliance-automation` |

## 13. Update & Patch Management

**Applies to:** Systems with update mechanisms, configuration drift, or versioned deployments.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| UPD-01 | Are updates cryptographically signed? Would unsigned or test-signed updates be rejected? | `edge-appliance`, `build-supply-chain` |
| UPD-02 | Can an attacker force a downgrade to a vulnerable version? | `edge-appliance`, `infra-mgmt` |
| UPD-03 | Should configuration changes emit security alerts by default? | `infra-mgmt`, `compliance-automation` |
| UPD-04 | Is device-side or node-side enforcement of signed configuration possible? | `edge-appliance` |
| UPD-05 | What behavior occurs on invalid or expired credentials during an update? | `edge-appliance`, `crypto-key-mgmt` |
| UPD-06 | For update distribution services spanning public, sovereign, and air-gapped clouds, should threat models be split per environment or maintained as a single threat surface? | `edge-appliance`, `infra-mgmt` |
| UPD-07 | How should manual-touch update distribution be replaced with full automation, and is current risk acceptance only temporary? | `edge-appliance`, `infra-mgmt` |
| UPD-08 | Can customers be forced to update vulnerable SDKs if they pin versions indefinitely? Should the service reject old SDK versions? | `edge-appliance`, `api-control-plane` |

## 14. Multi-Tenancy & Data Isolation

**Applies to:** Multi-tenant SaaS, shared infrastructure, or services where multiple customers share compute, storage, or networking.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| MT-01 | How is multi-tenancy enforced when multiple customers share infrastructure (data stores, event hubs, caches)? Can a compromised service identity cause cross-tenant leakage? | `api-control-plane`, `data-pipeline-etl` |
| MT-02 | Are there cryptographic guarantees preventing service identities from accessing data outside their intended tenant/subscription boundaries? | `api-control-plane`, `crypto-key-mgmt` |
| MT-03 | In shared vector databases, embedding stores, or AI indexes, how is per-tenant data isolation enforced? Can RAG pipelines leak context across tenants? | `ai-llm-service`, `data-pipeline-etl` |
| MT-04 | For multi-tenant fuzz testing or simulation platforms, can one user's test data or results be visible to another user? | `build-supply-chain`, `infra-mgmt` |
| MT-05 | When schema synchronization replicates across cloud boundaries, does schema-only read permission exist, or does the sync identity get full database access? | `data-pipeline-etl`, `infra-mgmt` |

## 15. Sovereign Cloud & Data Residency

**Applies to:** Systems operating in sovereign, air-gapped, or regulated cloud environments with data residency requirements.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| SOV-01 | Should cross-cloud data payloads be cryptographically signed (HMAC/MAC/signature) end-to-end, including intermediate transfer stages? | `data-pipeline-etl`, `crypto-key-mgmt` |
| SOV-02 | Should token containment be enforced to ensure sovereign tokens never leave the sovereign boundary and return to public cloud? | `identity-lifecycle`, `compliance-automation` |
| SOV-03 | Are data residency guarantees enforced at the application layer, or only via cloud region selection? | `compliance-automation`, `data-pipeline-etl` |
| SOV-04 | Is there a compensating control for lack of Entra ID / Conditional Access in sovereign environments? | `identity-lifecycle`, `compliance-automation` |
| SOV-05 | How is emergency ("break glass") access authenticated, time-bound, and audited in sovereign environments while preserving isolation? | `identity-lifecycle`, `compliance-automation` |
| SOV-06 | Can firewall logs and security telemetry be onboarded to SIEM for sovereign infrastructure, or are there air-gap restrictions? | `telemetry-pipeline`, `compliance-automation` |
| SOV-07 | For sovereign data transfers, can asymmetric signing with wrapped key embedding reduce PKI trust dependencies across classification boundaries? | `crypto-key-mgmt`, `data-pipeline-etl` |

## 16. Hardware Security & Attestation

**Applies to:** Systems with TPM, HSM, secure boot, firmware, IoT devices, or hardware root-of-trust dependencies.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| HW-01 | Are boot measurements (PCR, TPM, UEFI) actively validated and enforced at OS runtime? What happens if a measurement is inconsistent? | `edge-appliance`, `crypto-key-mgmt` |
| HW-02 | When PCR values change (kernel upgrade, firmware update), how is the new baseline securely distributed? Can an attacker freeze or replay old PCR values? | `edge-appliance`, `crypto-key-mgmt` |
| HW-03 | If disk encryption keys are released based on TPM state, what prevents booting with modified firmware, capturing the key, and rebooting with original firmware? | `edge-appliance`, `crypto-key-mgmt` |
| HW-04 | How does continuous attestation work when a node fails checks? Is the node evicted immediately, or is there a grace period allowing lateral movement? | `edge-appliance`, `k8s-extension` |
| HW-05 | Can HSM/TPM-bound key protection be used for long-term key escrow, and are keys separated per KMS version during migration? | `crypto-key-mgmt`, `edge-appliance` |
| HW-06 | What is the decommissioning and key revocation process when a hardware product reaches end-of-life? How are deployed devices made non-functional? | `edge-appliance`, `crypto-key-mgmt` |
| HW-07 | How are Endorsement Key (EK) certificate uniqueness and revocation enforced to prevent the same key from being registered across multiple organizations? | `edge-appliance`, `crypto-key-mgmt` |
| HW-08 | What CSR constraints are enforced to prevent malicious EKUs and path length abuse during certificate issuance? | `crypto-key-mgmt`, `edge-appliance` |

## 17. Bastion, Jumpbox & Remote Access

**Applies to:** Systems with bastion hosts, jumpboxes, RDP/SSH access, or supervised remote sessions.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| JUMP-01 | For SSH break-glass access to edge devices, how is host key validation bootstrapped securely when cloud connectivity is unavailable? | `edge-appliance`, `infra-mgmt` |
| JUMP-02 | Should SSH access to production infrastructure require hardware-backed certificates instead of static SSH keys? | `infra-mgmt`, `edge-appliance` |
| JUMP-03 | Can jumpbox images be made ephemeral (rebuilt per-session) to reduce blast radius? | `infra-mgmt`, `compliance-automation` |
| JUMP-04 | What approval process governs tool additions to escorted jumpbox environments? How is tool lifecycle formalized? | `infra-mgmt`, `compliance-automation` |
| JUMP-05 | How is supervised remote access cryptographically bound to a specific session and operator identity? | `identity-lifecycle`, `infra-mgmt` |
| JUMP-06 | Should screenshot/recording encryption be end-to-end from agent to operator, with decryption in browser or backend? | `infra-mgmt`, `crypto-key-mgmt` |

## 18. DNS & PKI Infrastructure

**Applies to:** Systems with DNS management, certificate infrastructure, PKI operations, or CT log processing.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| PKI-01 | Should Certificate Transparency (CT) log lists be validated for authenticity? How is DNS hijacking of CT log URLs prevented? | `crypto-key-mgmt`, `infra-mgmt` |
| PKI-02 | Should DNSSEC or equivalent DNS validation be mandatory for external log/configuration sources? | `infra-mgmt`, `api-control-plane` |
| PKI-03 | How should delegated DNS zone management enforce authorization claims in tokens? Should claims be scoped per-zone? | `infra-mgmt`, `identity-lifecycle` |
| PKI-04 | Can certificate rotation SLAs be enforced (e.g., 90-day max lifetime), and who audits compliance? | `crypto-key-mgmt`, `compliance-automation` |
| PKI-05 | Should RSA-2048 be upgraded to RSA-3072+ per current SDL guidance? What is the migration timeline? | `crypto-key-mgmt`, `all` |
| PKI-06 | For CT log parsers handling malformed certificate data, what input validation prevents exploitation of parsing vulnerabilities? | `crypto-key-mgmt`, `data-pipeline-etl` |

## 19. Deployment & Rollout Safety

**Applies to:** Systems with progressive rollout, canary deployments, feature flags, or runtime configuration.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| ROLL-01 | When SDKs fetch runtime configuration (feature flags) from dynamic configuration services, should payloads be signed to prevent DNS spoofing or CNAME redirection? | `api-control-plane`, `edge-appliance` |
| ROLL-02 | If a device or service rejects a tampered cloud configuration, does it fail-safe (stop) or fail-open (use stale config)? | `edge-appliance`, `api-control-plane` |
| ROLL-03 | For services that manage region-wide throttling/DDoS policies, what prevents a single storage account compromise from disabling protection across an entire region? | `infra-mgmt`, `api-control-plane` |
| ROLL-04 | Should throttling and rate-limiting configuration blobs be cryptographically signed for tamper detection? | `infra-mgmt`, `api-control-plane` |
| ROLL-05 | Can test flows be cryptographically distinguished from production partner flows to prevent test-to-prod confusion? | `build-supply-chain`, `infra-mgmt` |

## 20. Database & Storage Security

**Applies to:** Systems with databases, caches, object storage, or persistent data stores.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| DB-01 | Can encryption at rest be enforced for customer-managed etcd in Kubernetes clusters? | `k8s-extension`, `crypto-key-mgmt` |
| DB-02 | Are default database credentials (e.g., Cosmos DB, Redis, PostgreSQL) rotated from factory defaults before production use? | `infra-mgmt`, `all` |
| DB-03 | Are Cosmos DB default encryptions sufficient, or should customer-managed keys be required for sensitive workloads? | `crypto-key-mgmt`, `compliance-automation` |
| DB-04 | Can Azure Queue or Service Bus payloads be signed to prevent tampering between producer and consumer? | `data-pipeline-etl`, `crypto-key-mgmt` |
| DB-05 | For NFS/iSCSI storage, are authentication mechanisms enforced, or is access implicitly trusted based on network position? | `edge-appliance`, `infra-mgmt` |
| DB-06 | Should driver/artifact ingestion outputs be immutably sealed (legal holds, WORM) to prevent post-upload tampering? | `build-supply-chain`, `data-pipeline-etl` |

## 21. Compliance & Privacy Automation

**Applies to:** Systems subject to regulatory requirements, GDPR, FedRAMP, SDL, or handling personnel/HR data.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| COMP-01 | Must telemetry collection undergo GDPR/privacy review even for internal Microsoft users? | `telemetry-pipeline`, `compliance-automation` |
| COMP-02 | How should systems managing sensitive personnel data (clearances, background checks) balance double-encryption against operational complexity? | `compliance-automation`, `crypto-key-mgmt` |
| COMP-03 | Should personnel/HR systems implement dye testing and continuous privacy audits for all data flows? | `compliance-automation`, `data-pipeline-etl` |
| COMP-04 | When services are registered as "services" for compliance reasons despite being non-service assets (libraries), how should threat modeling scope be adjusted? | `compliance-automation`, `build-supply-chain` |
| COMP-05 | Should internal-only services with no business data still undergo full STRIDE threat modeling, or are abbreviated reviews acceptable? | `compliance-automation`, `all` |
| COMP-06 | How should activity logs be structured to support long-term exception auditing and regulatory compliance reviews? | `compliance-automation`, `telemetry-pipeline` |

## 22. Cross-Cloud Data Transfer & Integrity

**Applies to:** Systems transferring data between cloud environments, air-gapped deployments, or classification boundaries.

| ID | Question | Archetype Tags |
|----|----------|---------------|
| XFER-01 | Should blobs be signed on the source side and verified on the destination side before processing cross-cloud transfers? | `data-pipeline-etl`, `crypto-key-mgmt` |
| XFER-02 | Is payload ID brute-force protection enforced to prevent cross-pipeline quarantine object access? | `data-pipeline-etl`, `api-control-plane` |
| XFER-03 | How should out-of-band trusted flows be established for public key distribution across classification boundaries? | `crypto-key-mgmt`, `data-pipeline-etl` |
| XFER-04 | Should consumers of cross-cloud data validate manifest/hash integrity before processing? | `data-pipeline-etl`, `build-supply-chain` |
| XFER-05 | For proxy services transforming cross-cloud requests, can localhost, cluster metadata endpoints, and internal APIs be blocked to prevent SSRF? | `api-control-plane`, `data-pipeline-etl` |
| XFER-06 | How do on-premises systems validate cryptographic integrity of configurations managed offline via toolkits or sneakernet deployments? | `edge-appliance`, `crypto-key-mgmt` |

---

## Output Format

When mapping questions to a specific system, produce a section in `3-threatmodel.md` with this structure. This section is placed **after the DFD diagrams (and Summary View if present) but before the Element Table**, so reviewers see the high-level questions before element details:

```markdown
## Security Review Questions

> Questions derived from security review patterns for similar component types.
> Code-derived answers provided where possible; items requiring manual input flagged with 🔍.

### [Area Name]

| ID | Question | Relevant Component(s) | Status | Answer / Evidence |
|----|----------|----------------------|--------|-------------------|
| [ID] | [Question text] | [Mapped components] | [✅/⚠️/❌/🔍] | [Answer from code or "Not determinable from code"] |

### [Another Area Name]

| ID | Question | Relevant Component(s) | Status | Answer / Evidence |
|----|----------|----------------------|--------|-------------------|
| [ID] | [Question text] | [Mapped components] | [✅/⚠️/❌/🔍] | [Answer from code or "Not determinable from code"] |
```

**Status legend:**
- ✅ = Verified secure from code analysis
- ⚠️ = Partially addressed or configured but not enforced
- ❌ = Critical gap — not implemented
- 🔍 = **Requires manual verification** — include prompt: "Team to confirm: [specific question]"

**Rules:**
- Only include questions relevant to the system's component types and trust boundaries
- Group questions by the library's area/category headings using `###` sub-headings; do NOT flatten all questions into a single table
- Use one table per area and omit areas with no mapped questions
- Every ❌ should correspond to a finding in `5-securityfindings.md`
- Every 🔍 should have a specific, actionable prompt for the team
- Do not include questions where the category clearly does not apply (e.g., no AI questions for a pure infrastructure service)
