#!/usr/bin/env python3
"""
compile-patterns.py — Two-Tier Security Pattern Compilation Pipeline

Reads MeetingSecurityInfo transcript files, classifies them into archetypes,
extracts structured security data, and produces:
  - PUBLIC: security-patterns/archetypes/*.md + patterns-manifest.json
  - INTERNAL: internal-knowledge/systems/*.json + internal-manifest.json

Usage:
    python compile-patterns.py --source <MeetingSecurityInfo_dir> --skill <skill_dir> [--incremental]
"""

import argparse
import json
import os
import re
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

# ---------------------------------------------------------------------------
# Archetype classification rules — deterministic coarse filter
# ---------------------------------------------------------------------------

ARCHETYPE_INDICATORS: dict[str, dict[str, list[str]]] = {
    "api-control-plane": {
        "keywords": [
            "control plane", "resource provider", "REST API", "CRUD", "ARM",
            "OneRP", "API gateway", "APIM", "front door", "request routing",
            "tenant isolation", "multi-tenant", "rate limit", "throttl",
            "resource management", "subscription scop"
        ],
        "anti_keywords": ["data plane only", "agent-based collection"]
    },
    "telemetry-pipeline": {
        "keywords": [
            "telemetry", "monitoring pipeline", "Geneva", "OpenTelemetry",
            "Fluentd", "Prometheus", "collector", "exporter", "data collection",
            "metrics ingestion", "log collection", "MA agent", "MDSD",
            "monitoring agent", "collection rule", "DCR", "data collection endpoint"
        ],
        "anti_keywords": []
    },
    "crypto-key-mgmt": {
        "keywords": [
            "key vault", "certificate", "signing key", "HSM", "cryptograph",
            "key rotation", "DPAPI", "CNG", "X509", "cert-manager", "ACME",
            "code signing", "attestation", "key generation", "encryption key"
        ],
        "anti_keywords": []
    },
    "edge-appliance": {
        "keywords": [
            "edge", "on-prem", "appliance", "air-gapped", "disconnected",
            "customer hardware", "HCI", "Azure Stack", "IoT", "device",
            "firmware", "local admin", "offline", "factory", "bare metal",
            "SFF", "Data Box"
        ],
        "anti_keywords": ["edge function", "edge computing cloud"]
    },
    "k8s-extension": {
        "keywords": [
            "kubernetes", "k8s", "helm", "operator", "Arc extension",
            "namespace", "pod", "container orchestrat", "CRD",
            "custom resource", "AKS extension", "cluster"
        ],
        "anti_keywords": ["Container Insights standalone"]
    },
    "ai-llm-service": {
        "keywords": [
            "LLM", "GPT", "Azure OpenAI", "copilot AI", "prompt injection",
            "RAG", "retrieval augmented", "model inference", "AI inference",
            "natural language processing", "Semantic Kernel", "agent orchestrat",
            "guardrail", "content filter", "jailbreak", "prompt safety",
            "AI copilot", "model endpoint", "generative AI"
        ],
        "anti_keywords": ["threat model review", "security review"]
    },
    "build-supply-chain": {
        "keywords": [
            "build pipeline", "release", "supply chain", "OneBranch",
            "code signing", "artifact", "SBOM", "NuGet", "ACR",
            "container registry", "pipeline security", "SLSA",
            "deployment pipeline", "sovereign release"
        ],
        "anti_keywords": []
    },
    "identity-lifecycle": {
        "keywords": [
            "identity lifecycle", "account management", "credential reset",
            "JIT access", "PIM", "Entra ID", "Graph API", "Teams bot",
            "access grant", "role assignment", "MFA", "escort", "session manager",
            "privileged access", "DRI access"
        ],
        "anti_keywords": []
    },
    "infra-mgmt": {
        "keywords": [
            "infrastructure management", "resource provider", "VM provisioning",
            "VM management", "network management", "Fabric Controller",
            "ARM template", "Bicep", "Terraform", "chaos studio", "environment management",
            "regulated environment", "ConfigGuard", "server management",
            "jumpbox", "lab management", "fleet management"
        ],
        "anti_keywords": []
    },
    "data-pipeline-etl": {
        "keywords": [
            "data pipeline", "ETL", "data ingestion", "aggregation",
            "data transfer", "CTS", "warm path", "snapshot", "data flow",
            "batch processing", "data movement", "cross-source"
        ],
        "anti_keywords": []
    },
    "observability-query": {
        "keywords": [
            "observability", "query service", "log analytics", "dashboard",
            "Kusto", "KQL", "Application Insights", "Grafana",
            "diagnostic", "analytics", "read-only access", "data explorer"
        ],
        "anti_keywords": []
    },
    "compliance-automation": {
        "keywords": [
            "compliance", "policy automation", "audit", "regulatory",
            "attestation", "governance", "Azure Policy", "Defender",
            "Sentinel", "compliance manager", "federal compliance",
            "evidence collection"
        ],
        "anti_keywords": []
    },
}

# Manual override map for known ambiguous systems
MANUAL_OVERRIDES: dict[str, list[str]] = {
    # Filename substring → forced archetype list
    "Geneva Warm Path": ["data-pipeline-etl", "telemetry-pipeline"],
    "Container Insights": ["telemetry-pipeline"],
    "Federal Compliance Copilot": ["ai-llm-service", "compliance-automation"],
    "ConfigGuard": ["infra-mgmt", "compliance-automation"],
    "Escort Session Manager": ["identity-lifecycle"],
    "Sovereign Release Manager": ["build-supply-chain"],
    "Hybrid Resource Provider": ["k8s-extension", "infra-mgmt"],
    "Data Box Edge": ["edge-appliance"],
    "Device Update for IoT": ["edge-appliance"],
    "AEP AI Copilot": ["ai-llm-service", "edge-appliance"],
    "Azure Edge AI": ["ai-llm-service", "edge-appliance"],
    "ReconAI": ["ai-llm-service"],
    "Bug Classifier": ["ai-llm-service"],
    "Azure Alerts Control Plane": ["api-control-plane"],
    "Azure Alerts Data Plane": ["api-control-plane", "telemetry-pipeline"],
    "Azure Monitor Essentials": ["api-control-plane", "telemetry-pipeline"],
    "Azure Monitor Data Collection": ["telemetry-pipeline"],
    "Azure Log Analytics": ["observability-query"],
    "Application Insights": ["observability-query", "telemetry-pipeline"],
    "Azure Profiler": ["observability-query"],
    "Azure Watson": ["observability-query"],
    "Workbooks & Experiences": ["observability-query"],
    "Azure Chaos Studio": ["infra-mgmt"],
    "Regulated Environment Management": ["infra-mgmt", "compliance-automation"],
    "Azure Stack HCI": ["edge-appliance"],
    "Azure Stack Common": ["edge-appliance"],
    "Azure Stack Compute": ["edge-appliance"],
    "Azure Stack Labs": ["edge-appliance"],
    "Azure Stack Partner": ["edge-appliance"],
    "Azure Local": ["edge-appliance"],
    "AzureLocal-Observability": ["edge-appliance", "telemetry-pipeline"],
    "Azure Sphere": ["edge-appliance"],
    "Azure IoT Hub": ["edge-appliance"],
    "Azure KMS": ["crypto-key-mgmt"],
    "Microsoft Key Management": ["crypto-key-mgmt"],
    "ENS_EWS_Certificate": ["crypto-key-mgmt"],
    "EnS_EWS_Encryption": ["crypto-key-mgmt"],
    "EnS_EWS_Fortos_Secrets": ["crypto-key-mgmt"],
    "Root Certificate Management": ["crypto-key-mgmt"],
    "Windows Build Signing": ["build-supply-chain", "crypto-key-mgmt"],
    "OneFuzz": ["build-supply-chain"],
    "Binary AtteStation": ["build-supply-chain"],
    "VCPkg and NuGet": ["build-supply-chain"],
    "Cloud Transfer Service": ["data-pipeline-etl"],
    "CloudTransferService": ["data-pipeline-etl"],
    "CTS Core": ["data-pipeline-etl"],
    "CTS Coupler": ["data-pipeline-etl"],
    "CTS Portal": ["data-pipeline-etl"],
    "CTS SQL": ["data-pipeline-etl"],
    "AzureDataInfraSync": ["data-pipeline-etl"],
    "Foundry on Arc": ["k8s-extension"],
    "Workload Orchestration": ["k8s-extension"],
    "Sovereign Emergency Path": ["identity-lifecycle"],
    "Supervised RDP": ["identity-lifecycle"],
    "Jumpbox": ["identity-lifecycle"],
    "NCOE Jumpboxes": ["identity-lifecycle"],
    "Fleet Diagnostics": ["edge-appliance", "observability-query"],
    "One-Collect": ["edge-appliance", "observability-query"],
    "Network Monitoring": ["observability-query", "telemetry-pipeline"],
    "ServerFun.Shared.GuestOS": ["telemetry-pipeline"],
    "Geneva Synthetics": ["telemetry-pipeline"],
    "MDM": ["telemetry-pipeline"],
    "Dialtone": ["infra-mgmt"],
    "MTP Sovereign": ["infra-mgmt"],
    "International Sovereign": ["infra-mgmt"],
    "MSUpdate": ["build-supply-chain"],
    "WSUS": ["build-supply-chain"],
    "Imaging PROD": ["build-supply-chain"],
    "IPAK PROD": ["build-supply-chain"],
    "Driver Servicing": ["build-supply-chain"],
    "Device_Platform-Foreign": ["build-supply-chain"],
    "CA Audit Letter": ["compliance-automation"],
    "Mission Trust": ["compliance-automation"],
    "Security at Scale": ["compliance-automation"],
    "Drift-In-Parity": ["compliance-automation"],
    "SafeDNS": ["api-control-plane"],
    "Azure Throttling": ["api-control-plane"],
    "Azure Notification": ["api-control-plane"],
    "Mobile Plans": ["api-control-plane"],
    "Windows Admin Center": ["edge-appliance", "infra-mgmt"],
    "Windows Server Catalog": ["infra-mgmt"],
    "Video Indexer": ["ai-llm-service", "data-pipeline-etl"],
    "Planetary Computer": ["data-pipeline-etl", "ai-llm-service"],
    "ALDO Winfield": ["edge-appliance"],
}

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Threat:
    id: str
    title: str
    stride_category: str = ""
    severity: str = ""
    description: str = ""
    status: str = "approved"

@dataclass
class Decision:
    id: str
    title: str
    approver_role: str = ""
    rationale: str = ""
    alternatives_considered: str = ""

@dataclass
class Risk:
    id: str
    title: str
    condition: str = ""
    mitigating_controls: str = ""
    review_cadence: str = ""

@dataclass
class Action:
    id: str
    title: str
    owner_role: str = ""
    status: str = "open"
    priority: str = "Medium"

@dataclass
class SystemRecord:
    system_id: str
    display_name: str
    archetypes: list[str] = field(default_factory=list)
    review_date: str = ""
    source_file: str = ""
    repo_patterns: list[str] = field(default_factory=list)
    tech_stack: dict = field(default_factory=lambda: {"deployment": [], "auth": [], "technologies": []})
    approved_threats: list[dict] = field(default_factory=list)
    approved_decisions: list[dict] = field(default_factory=list)
    accepted_risks: list[dict] = field(default_factory=list)
    open_actions: list[dict] = field(default_factory=list)
    review_questions_asked: list[str] = field(default_factory=list)

# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def extract_system_name(filename: str) -> str:
    """Extract system name from filename."""
    name = filename.replace("Threat Model Review Meeting - ", "").replace(".md", "")
    return name.strip()

def to_system_id(name: str) -> str:
    """Convert system name to kebab-case ID."""
    s = re.sub(r'[^a-zA-Z0-9\s-]', '', name.lower())
    s = re.sub(r'\s+', '-', s.strip())
    s = re.sub(r'-+', '-', s)
    return s[:60]

def parse_sections(content: str) -> dict[str, str]:
    """Parse markdown into sections by ## headers."""
    sections: dict[str, str] = {}
    current_header = ""
    current_body: list[str] = []

    for line in content.split('\n'):
        if line.startswith('## '):
            if current_header:
                sections[current_header] = '\n'.join(current_body).strip()
            current_header = line.lstrip('#').strip()
            # Normalize numbered sections: "1. Meeting Overview" → "Meeting Overview"
            current_header = re.sub(r'^\d+\.?\d*\s*', '', current_header).strip()
            current_body = []
        else:
            current_body.append(line)

    if current_header:
        sections[current_header] = '\n'.join(current_body).strip()

    return sections

def extract_date(content: str) -> str:
    """Extract review date from content."""
    # Look for ## Date: line
    m = re.search(r'##\s*Date:\s*(.+)', content)
    if m:
        date_str = m.group(1).strip()
        # Try to parse common formats
        for fmt in ["%B %d, %Y", "%B %d, %Y, %I:%M", "%Y-%m-%d"]:
            try:
                # Strip time portions after comma-separated date
                clean = re.split(r',\s*\d{1,2}:\d{2}', date_str)[0]
                dt = datetime.strptime(clean.strip().rstrip(','), fmt)
                return dt.strftime("%Y-%m-%d")
            except ValueError:
                continue
    return ""

def extract_repo_patterns(content: str) -> list[str]:
    """Extract repo/service name patterns for similarity matching."""
    patterns = set()
    # Look for repo URLs
    for m in re.finditer(r'(?:github|dev\.azure)\.com/[^\s)]+', content):
        url = m.group(0)
        # Extract repo name from URL
        parts = url.rstrip('/').split('/')
        if len(parts) >= 2:
            patterns.add(parts[-1])

    # Look for service names in the context section
    for m in re.finditer(r'(?:service|system|component|product):\s*\*?\*?(.+?)(?:\*?\*?|\n)', content, re.IGNORECASE):
        patterns.add(m.group(1).strip())

    return list(patterns)[:10]

def extract_tech_stack(content: str) -> dict:
    """Extract tech stack indicators from content."""
    tech: dict[str, list[str]] = {"deployment": [], "auth": [], "technologies": []}

    deployment_terms = {
        "on-prem": r'\bon[- ]prem', "cloud": r'\bcloud\b', "hybrid": r'\bhybrid\b',
        "kubernetes": r'\bkubernetes|k8s|AKS\b', "edge": r'\bedge\b',
        "multi-region": r'\bmulti[- ]region', "multi-tenant": r'\bmulti[- ]tenant'
    }
    auth_terms = {
        "managed-identity": r'\bmanaged identity|MSI\b', "certificate-auth": r'\bcertificate[- ]auth|cert[- ]based|X\.?509\b',
        "OAuth2": r'\bOAuth|bearer token\b', "RBAC": r'\bRBAC\b', "Entra-ID": r'\bEntra|AAD|Azure AD\b',
        "SAS-token": r'\bSAS token|SAS key\b', "APPKI": r'\bAPPKI|AVPKI\b'
    }
    tech_terms = {
        "Azure-Key-Vault": r'\bKey Vault\b', "Cosmos-DB": r'\bCosmos ?DB\b',
        "Event-Hub": r'\bEvent ?Hub\b', "Kubernetes": r'\bKubernetes|AKS\b',
        "Azure-OpenAI": r'\bAzure OpenAI|AOAI\b', "Geneva": r'\bGeneva\b',
        "ARM": r'\bARM\b', "Terraform": r'\bTerraform\b', "Helm": r'\bHelm\b',
        "Docker": r'\bDocker|container\b', "IoT-Hub": r'\bIoT Hub\b',
        "Arc": r'\bArc extension|Azure Arc\b'
    }

    text_lower = content.lower()
    for label, pat in deployment_terms.items():
        if re.search(pat, content, re.IGNORECASE):
            tech["deployment"].append(label)
    for label, pat in auth_terms.items():
        if re.search(pat, content, re.IGNORECASE):
            tech["auth"].append(label)
    for label, pat in tech_terms.items():
        if re.search(pat, content, re.IGNORECASE):
            tech["technologies"].append(label)

    return tech

def extract_threats(sections: dict[str, str], system_id: str) -> list[dict]:
    """Extract threats from security topics and threats sections."""
    threats: list[dict] = []
    counter = 1

    for section_key in ["Security Topics Discussed", "Threats, Risks & Concerns"]:
        text = sections.get(section_key, "")
        if not text:
            continue

        # Split by ### subsections or bullet points
        items = re.split(r'###\s+', text)
        for item in items:
            item = item.strip()
            if len(item) < 20:
                continue
            # Extract first meaningful line as title
            lines = [l.strip() for l in item.split('\n') if l.strip() and not l.strip().startswith('---')]
            if not lines:
                continue
            title = re.sub(r'^[A-Z]\.\s*', '', lines[0])[:200]
            threats.append(asdict(Threat(
                id=f"T-{system_id[:20].upper()}-{counter:03d}",
                title=title,
                description=item[:500],
                severity="High",
                status="approved"
            )))
            counter += 1

    return threats

def extract_decisions(sections: dict[str, str], system_id: str) -> list[dict]:
    """Extract approved decisions."""
    decisions: list[dict] = []
    text = sections.get("Security Decisions Made", "")
    if not text:
        return decisions

    counter = 1
    # Split by numbered items or bullet blocks
    items = re.split(r'\n(?=\d+\.\s|\-\s\*\*|\-\s\[)', text)
    for item in items:
        item = item.strip()
        if len(item) < 20:
            continue
        lines = [l.strip() for l in item.split('\n') if l.strip()]
        if not lines:
            continue
        title = lines[0].lstrip('0123456789.-[] ').strip()[:200]

        # Look for approver
        approver = ""
        for line in lines:
            if re.search(r'approv|decided|agreed|approved by', line, re.IGNORECASE):
                # Extract name pattern
                m = re.search(r'(?:by|—)\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)', line)
                if m:
                    approver = "Security reviewer"  # anonymize
                break

        rationale = ""
        for line in lines[1:]:
            if re.search(r'rationale|because|reason|due to', line, re.IGNORECASE):
                rationale = line[:300]
                break

        decisions.append(asdict(Decision(
            id=f"D-{system_id[:20].upper()}-{counter:03d}",
            title=title,
            approver_role=approver or "Security reviewer",
            rationale=rationale
        )))
        counter += 1

    return decisions

def extract_risks(sections: dict[str, str], system_id: str) -> list[dict]:
    """Extract accepted risks."""
    risks: list[dict] = []
    counter = 1

    # Look in both threats section and decisions for accepted risks
    for section_key in ["Threats, Risks & Concerns", "Security Decisions Made"]:
        text = sections.get(section_key, "")
        if not text:
            continue
        # Look for lines mentioning "accepted", "acceptable", "risk accepted"
        for line in text.split('\n'):
            if re.search(r'accept(?:ed|able)|acknowledged risk|known risk|deferred', line, re.IGNORECASE):
                title = line.lstrip('-*[] ').strip()[:200]
                if len(title) > 15:
                    risks.append(asdict(Risk(
                        id=f"R-{system_id[:20].upper()}-{counter:03d}",
                        title=title,
                        condition="As documented in security review",
                        review_cadence="Per next review cycle"
                    )))
                    counter += 1

    return risks

def extract_actions(sections: dict[str, str], system_id: str) -> list[dict]:
    """Extract action items."""
    actions: list[dict] = []
    text = sections.get("Security Action Items", "")
    if not text:
        return actions

    counter = 1
    for line in text.split('\n'):
        if re.match(r'\s*-\s*\[', line):
            title = re.sub(r'^\s*-\s*\[\s*[xX ]?\s*\]\s*', '', line).strip()
            # Strip owner info for public use
            title_clean = re.split(r'\s*—\s*Owner:', title)[0].strip()[:200]
            if len(title_clean) > 10:
                actions.append(asdict(Action(
                    id=f"A-{system_id[:20].upper()}-{counter:03d}",
                    title=title_clean,
                    owner_role="Engineering",
                    status="open"
                )))
                counter += 1

    return actions

def extract_review_questions(sections: dict[str, str]) -> list[str]:
    """Extract questions asked during the review."""
    questions = []
    for section_key in ["Security Topics Discussed", "Open Security Questions"]:
        text = sections.get(section_key, "")
        for m in re.finditer(r'"([^"]{20,200}\?)"', text):
            questions.append(m.group(1))
        for m in re.finditer(r'>\s*"([^"]{20,200}\?)"', text):
            questions.append(m.group(1))
    return list(set(questions))[:15]

# ---------------------------------------------------------------------------
# Archetype classification
# ---------------------------------------------------------------------------

def classify_archetypes(filename: str, content: str) -> list[str]:
    """Classify a meeting file into archetype(s)."""
    # Check manual overrides first
    for pattern, archetypes in MANUAL_OVERRIDES.items():
        if pattern.lower() in filename.lower():
            return archetypes

    matched = []
    content_lower = content.lower()

    for archetype_id, indicators in ARCHETYPE_INDICATORS.items():
        score = 0
        for kw in indicators["keywords"]:
            if kw.lower() in content_lower:
                score += 1
        # Apply anti-keywords
        for akw in indicators.get("anti_keywords", []):
            if akw.lower() in content_lower:
                score -= 2

        if score >= 3:
            matched.append((archetype_id, score))

    # Sort by score descending, return archetype IDs
    matched.sort(key=lambda x: x[1], reverse=True)
    return [m[0] for m in matched[:4]]  # max 4 archetypes per system

# ---------------------------------------------------------------------------
# Anonymization (allowlist approach)
# ---------------------------------------------------------------------------

def anonymize_text(text: str) -> str:
    """Anonymize text using allowlist approach — strip specific identifiers."""
    result = text
    # Remove person names (pattern: First Last with optional ⭐)
    result = re.sub(r'\b[A-Z][a-z]+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\s*⭐?', 'a reviewer', result)
    # Remove repo URLs
    result = re.sub(r'https?://(?:github|dev\.azure)\.com/[^\s)]+', '[repo-url]', result)
    # Remove Azure resource names (pattern: lowercase with hyphens in resource context)
    result = re.sub(r'(?:resource[/:]|https://)[a-z0-9-]+\.(?:azure|microsoft)\.[a-z.]+[^\s]*', '[azure-resource]', result)
    # Remove specific config keys
    result = re.sub(r'[A-Z_]{3,}(?:_[A-Z_]+)+', '[config-key]', result)
    # Remove IP addresses
    result = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[ip-address]', result)
    # Remove email addresses
    result = re.sub(r'[\w.-]+@[\w.-]+\.\w+', '[email]', result)
    return result

# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def process_file(filepath: Path) -> Optional[SystemRecord]:
    """Process a single meeting transcript file."""
    content = filepath.read_text(encoding='utf-8', errors='replace')
    filename = filepath.name

    system_name = extract_system_name(filename)
    system_id = to_system_id(system_name)

    if len(content) < 200:
        print(f"  SKIP (too short): {filename}")
        return None

    archetypes = classify_archetypes(filename, content)
    if not archetypes:
        print(f"  WARN (no archetype match): {filename}")
        archetypes = ["uncategorized"]

    sections = parse_sections(content)

    record = SystemRecord(
        system_id=system_id,
        display_name=system_name,
        archetypes=archetypes,
        review_date=extract_date(content),
        source_file=filename,
        repo_patterns=extract_repo_patterns(content),
        tech_stack=extract_tech_stack(content),
        approved_threats=extract_threats(sections, system_id),
        approved_decisions=extract_decisions(sections, system_id),
        accepted_risks=extract_risks(sections, system_id),
        open_actions=extract_actions(sections, system_id),
        review_questions_asked=extract_review_questions(sections),
    )

    return record

def write_system_json(record: SystemRecord, output_dir: Path):
    """Write internal per-system JSON file."""
    outpath = output_dir / f"{record.system_id}.json"
    data = asdict(record)
    outpath.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')

def write_internal_manifest(records: list[SystemRecord], output_dir: Path):
    """Write internal-manifest.json."""
    archetype_systems: dict[str, list[str]] = {}
    for rec in records:
        for arch in rec.archetypes:
            archetype_systems.setdefault(arch, []).append(rec.system_id)

    manifest = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_count": len(records),
        "status": "complete",
        "archetype_systems": archetype_systems,
    }

    outpath = output_dir / "internal-manifest.json"
    outpath.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')

def update_patterns_manifest(records: list[SystemRecord], manifest_path: Path):
    """Update patterns-manifest.json with generation timestamp and archetype stats."""
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    manifest["generated_at"] = datetime.now(timezone.utc).isoformat()

    # Add per-archetype source counts
    archetype_counts: dict[str, int] = {}
    for rec in records:
        for arch in rec.archetypes:
            archetype_counts[arch] = archetype_counts.get(arch, 0) + 1

    for entry in manifest.get("archetypes", []):
        entry["source_count"] = archetype_counts.get(entry["id"], 0)

    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding='utf-8')

def main():
    parser = argparse.ArgumentParser(description="Compile security patterns from meeting transcripts")
    parser.add_argument("--source", required=True, help="Path to MeetingSecurityInfo directory")
    parser.add_argument("--skill", required=True, help="Path to threat-model-analyst skill directory")
    parser.add_argument("--incremental", action="store_true", help="Only process new/modified files")
    args = parser.parse_args()

    source_dir = Path(args.source)
    skill_dir = Path(args.skill)

    if not source_dir.exists():
        print(f"ERROR: Source directory not found: {source_dir}")
        return 1

    # Paths
    internal_dir = skill_dir / "internal-knowledge"
    systems_dir = internal_dir / "systems"
    patterns_dir = skill_dir / "references" / "security-patterns"
    manifest_path = patterns_dir / "patterns-manifest.json"

    # Ensure directories exist
    systems_dir.mkdir(parents=True, exist_ok=True)

    # Find meeting files
    meeting_files = sorted(source_dir.glob("Threat Model Review Meeting*.md"))
    print(f"Found {len(meeting_files)} meeting transcript files")

    if args.incremental:
        # Check existing system files and skip unchanged sources
        existing_systems = {f.stem for f in systems_dir.glob("*.json")}
        print(f"Incremental mode: {len(existing_systems)} existing system records")

    # Process all files
    records: list[SystemRecord] = []
    archetype_data: dict[str, list[SystemRecord]] = {}

    for filepath in meeting_files:
        print(f"Processing: {filepath.name}")
        record = process_file(filepath)
        if record:
            records.append(record)
            for arch in record.archetypes:
                archetype_data.setdefault(arch, []).append(record)

    print(f"\nProcessed {len(records)} files successfully")
    print(f"Archetype distribution:")
    for arch, recs in sorted(archetype_data.items()):
        print(f"  {arch}: {len(recs)} systems")

    # Write internal system JSONs
    for record in records:
        write_system_json(record, systems_dir)
    print(f"\nWrote {len(records)} system JSON files to {systems_dir}")

    # Write internal manifest
    write_internal_manifest(records, internal_dir)
    print(f"Wrote internal-manifest.json")

    # Update public manifest with generation stats
    if manifest_path.exists():
        update_patterns_manifest(records, manifest_path)
        print(f"Updated patterns-manifest.json with source counts")

    # Summary
    print(f"\n{'='*60}")
    print(f"Compilation complete!")
    print(f"  Total files processed: {len(records)}")
    print(f"  Archetypes populated: {len(archetype_data)}")
    print(f"  Internal systems: {systems_dir}")
    print(f"  Public patterns: {patterns_dir}")
    print(f"{'='*60}")

    return 0

if __name__ == "__main__":
    exit(main())
