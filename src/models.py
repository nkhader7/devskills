"""Data models for devskills framework."""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class TokenCost:
    estimate: int
    model_agnostic: bool
    unit: str


@dataclass
class Detection:
    regex: Optional[str] = None
    entropy: Optional[float] = None
    keywords: Optional[List[str]] = None
    path_filter: Optional[str] = None
    allowlist: Optional[List[str]] = None


@dataclass
class Remediation:
    action: str
    docs: str


@dataclass
class ReportMeta:
    finding_type: str
    impact: str


@dataclass
class Skill:
    id: str
    version: str
    name: str
    description: str
    category: str
    severity: str
    tags: List[str]
    token_cost: TokenCost
    detection: Detection
    remediation: Remediation
    report: ReportMeta

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Skill":
        tc = data["token_cost"]
        det = data.get("detection", {})
        rem = data["remediation"]
        rep = data["report"]
        return cls(
            id=data["id"],
            version=data["version"],
            name=data["name"],
            description=data["description"],
            category=data["category"],
            severity=data["severity"],
            tags=data.get("tags", []),
            token_cost=TokenCost(
                estimate=tc["estimate"],
                model_agnostic=tc["model_agnostic"],
                unit=tc["unit"],
            ),
            detection=Detection(
                regex=det.get("regex"),
                entropy=det.get("entropy"),
                keywords=det.get("keywords"),
                path_filter=det.get("path_filter"),
                allowlist=det.get("allowlist"),
            ),
            remediation=Remediation(action=rem["action"], docs=rem.get("docs", "")),
            report=ReportMeta(finding_type=rep["finding_type"], impact=rep["impact"]),
        )


@dataclass
class Finding:
    skill_id: str
    skill_name: str
    severity: str
    file_path: str
    line_number: int
    matched_text: str
    masked_secret: str
    token_cost: int
    finding_type: str
    impact: str


@dataclass
class Report:
    scan_id: str
    timestamp: str
    target: str
    findings: List[Finding] = field(default_factory=list)
    token_cost_total: int = 0

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.token_cost_total += finding.token_cost

    def findings_by_severity(self) -> Dict[str, List[Finding]]:
        result: Dict[str, List[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.severity, []).append(f)
        return result
