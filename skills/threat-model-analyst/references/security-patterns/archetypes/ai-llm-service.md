# AI / LLM Inference & Reasoning Service

> Archetype ID: `ai-llm-service` | Schema Version: 1.0

## Component Characteristics

Services that accept natural language or structured input, process through AI/ML models, and produce outputs that may drive downstream actions. These systems face unique threats around prompt manipulation, model abuse, and the non-deterministic nature of outputs.

**Defining traits:**
- Accepts user-controlled natural language input processed by ML models
- Outputs may drive automated actions (tool calling, code execution, data access)
- May use RAG (Retrieval-Augmented Generation) over potentially sensitive data
- Non-deterministic behavior makes traditional input validation insufficient
- Model weights and training data are high-value intellectual property

## Review Questions

1. **Prompt injection:** How does the service distinguish between system instructions and user input? Is there a mechanism to prevent user input from overriding system behavior?
2. **Tool calling / code execution:** If the model can invoke tools or execute code, what are the permission boundaries? Can the model escalate beyond its intended scope?
3. **Data access via RAG:** What data sources feed the RAG index? Can a user extract data they shouldn't have access to by crafting queries that surface indexed content?
4. **Output sanitization:** Are model outputs validated before being rendered to users or passed to downstream systems? Can outputs contain executable content (XSS, SQL injection)?
5. **Rate limiting and abuse:** How is abuse prevented (excessive usage, content policy violations, model extraction attempts)?
6. **Data leakage through model responses:** Can the model reveal training data, system prompts, or information from other users' sessions?
7. **Model supply chain:** How are model weights sourced, verified, and protected? Is there integrity validation on model files?

## Common Threat Patterns

| Threat Pattern | STRIDE Category | Frequency | Typical Severity |
|---|---|---|---|
| Prompt injection overriding system instructions to perform unauthorized actions | Tampering | High | Critical |
| Data exfiltration through RAG index query manipulation | Information Disclosure | High | High |
| Tool calling escalation beyond intended permission scope | Elevation of Privilege | Medium | Critical |
| Model output containing executable content (XSS, injection) | Tampering | Medium | High |
| System prompt extraction revealing service architecture and policies | Information Disclosure | High | Medium |
| Cross-session data leakage through model context contamination | Information Disclosure | Medium | High |
| Jailbreak attacks bypassing content safety guardrails | Tampering | High | Medium |
| Model denial of service through adversarial inputs causing excessive compute | Denial of Service | Medium | Medium |

## Decision Patterns

| Decision Area | Common Resolution | Rationale |
|---|---|---|
| Prompt injection defense | Multi-layer: input sanitization + output validation + system/user message separation + canary tokens | No single defense is sufficient; defense in depth required |
| Tool calling permissions | Explicit allowlist of tools per context; human-in-the-loop for high-risk operations | Open tool access has led to unintended data modification |
| RAG access control | Enforce user-level permissions on RAG index queries; filter results before feeding to model | Index-level access without user RBAC creates data boundary bypass |
| Output handling | Treat all model outputs as untrusted; sanitize before rendering or executing | Model outputs are not validated by the model itself |
| Content safety | Layered guardrails: input filter + output filter + model-level alignment | Single-layer guardrails are routinely bypassed |

## Acceptable Risk Patterns

| Risk Condition | Acceptance Criteria | Typical Mitigating Controls |
|---|---|---|
| Model may occasionally surface non-sensitive training data in responses | Training data does not contain PII or secrets; fine-tuning data is curated | Training data review process; output monitoring for sensitive content |
| System prompt partially inferable through careful probing | System prompt contains no secrets; service security doesn't depend on prompt secrecy | Defense in depth; don't embed secrets in prompts; rotate prompt strategies |
| RAG responses may include tangentially related content from same access tier | All content in index is at same or lower sensitivity than user's access level | Per-user RBAC on index; content classification before indexing |

## Common Action Items

- [ ] Implement structured system/user message separation with injection detection
- [ ] Add output sanitization layer between model response and user rendering
- [ ] Enforce per-user RBAC on RAG index queries
- [ ] Define explicit tool calling permission boundaries with allowlists
- [ ] Deploy input and output content safety guardrails
- [ ] Implement rate limiting and abuse detection per user/session
