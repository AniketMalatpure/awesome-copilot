# Build / Release / Supply-Chain Infrastructure

> Archetype ID: `build-supply-chain` | Schema Version: 1.0

## Component Characteristics

Systems that build, sign, attest, and distribute software artifacts. Protecting the integrity of the software supply chain from code commit to production deployment.

**Defining traits:**
- Transforms source code into deployable artifacts (binaries, containers, packages)
- Often involves signing and attestation of build outputs
- Pipeline definitions are code (YAML) stored in repositories
- Build agents may have access to production credentials for deployment
- Compromising the build system can inject malicious code into all downstream consumers

## Review Questions

1. **Build isolation:** Are builds isolated from each other? Can one build job influence another (shared filesystem, environment variables, cached dependencies)?
2. **Signing key protection:** Where are code-signing keys stored? Are they accessible to the build pipeline directly, or is signing performed by an isolated service?
3. **Dependency integrity:** How are external dependencies verified? Is there SBOM generation and vulnerability scanning?
4. **Pipeline definition security:** Who can modify pipeline definitions? Is there branch protection and review requirements for pipeline YAML changes?
5. **Credential exposure:** What credentials are available to build agents? Can a compromised build step exfiltrate production credentials?
6. **Artifact integrity:** Can build outputs be tampered with after signing? Is there end-to-end integrity verification from build to deployment?
7. **Third-party action/task trust:** Are third-party pipeline actions/tasks pinned to specific versions? Can an upstream dependency update inject malicious code?

## Common Threat Patterns

| Threat Pattern | STRIDE Category | Frequency | Typical Severity |
|---|---|---|---|
| Malicious code injection through compromised build dependency | Tampering | High | Critical |
| Signing key extraction from build pipeline | Information Disclosure | Medium | Critical |
| Pipeline definition manipulation to inject malicious build steps | Tampering | Medium | Critical |
| Build artifact tampering between build and deployment | Tampering | Medium | High |
| Credential exfiltration from build agent environment | Information Disclosure | High | High |
| Third-party action supply chain attack (malicious upstream update) | Tampering | Medium | Critical |
| Insufficient build isolation allowing cross-job contamination | Tampering | Medium | High |

## Decision Patterns

| Decision Area | Common Resolution | Rationale |
|---|---|---|
| Signing architecture | Isolated signing service; build pipeline submits hash, receives signature; keys never on build agents | Build agent compromise should not enable arbitrary artifact signing |
| Dependency verification | Pin all dependencies to specific hashes; automated SBOM generation; vulnerability scanning in pipeline | Version-only pinning allows compromised package substitution |
| Pipeline protection | Branch protection on pipeline YAML; require review from security team for pipeline changes | Unreviewed pipeline changes are equivalent to arbitrary code execution |
| Build agent credentials | Short-lived, scoped tokens; no persistent credentials on agents; federated identity | Persistent credentials on agents survive beyond the build and can be exfiltrated |
| Artifact attestation | SLSA Level 3+ attestation; provenance metadata attached to all artifacts | Attestation enables downstream consumers to verify artifact origin |

## Acceptable Risk Patterns

| Risk Condition | Acceptance Criteria | Typical Mitigating Controls |
|---|---|---|
| Build agents have temporary access to staging credentials | Credentials are short-lived (< 1 hour); staging has no production data | Token expiry enforcement; credential rotation per build |
| Third-party dependencies not all hash-pinned | Major frameworks only version-pinned; hash pinning for critical security dependencies | Automated vulnerability scanning; lockfile integrity checks |
| SBOM not yet generated for all artifacts | SBOM generation rolling out; high-priority artifacts covered first | Priority list maintained; quarterly progress review |

## Common Action Items

- [ ] Migrate code signing to isolated signing service (keys never on build agents)
- [ ] Pin all critical dependencies to cryptographic hashes, not just versions
- [ ] Implement SLSA Level 3 attestation for production artifacts
- [ ] Add branch protection and mandatory review for pipeline YAML changes
- [ ] Replace persistent build agent credentials with short-lived federated tokens
