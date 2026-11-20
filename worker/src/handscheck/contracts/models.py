"""Job, result and catalog models. Additive changes keep CONTRACT_VERSION; breaking ones bump it."""

from datetime import datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

CONTRACT_VERSION = 1


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class JobKind(StrEnum):
    """What a job does. `scan` connects to the host and runs the specialists; `watch` is the same with only
    the watch agents (rules only, every 15-60 min, M7); `recon` maps a host and proposes per-host agent
    settings (M7c; read-only, works without Claude); `plan` is the planner's run plan (M7c, no host access);
    the role kinds (M5c) run one role agent on data the
    control plane puts in the job: `verify` (verifier on stored findings, with the read-only tool when `host`
    is set), `investigate` (a follow-up question, read-only tool), `triage` and `compose` (no host access).
    Each kind has its own input section on the Job (`verify`, `triage`, ...) and its own output section on the
    Result; a new kind (e.g. Track S `analyze`) adds a section, not a field on the existing ones."""

    scan = "scan"
    watch = "watch"
    recon = "recon"
    plan = "plan"
    verify = "verify"
    triage = "triage"
    compose = "compose"
    explain = "explain"
    investigate = "investigate"
    remediate = "remediate"


ROLE_KINDS = (
    JobKind.verify,
    JobKind.triage,
    JobKind.compose,
    JobKind.explain,
    JobKind.investigate,
    JobKind.plan,
)
"""Kinds that only run a Claude role agent: a worker without Anthropic credentials doesn't lease them."""


class HostTarget(_Model):
    """How to reach the host. The control plane decrypts the key (KMS) just for this job."""

    host_id: str
    name: str
    address: str
    port: int = Field(default=22, ge=1, le=65535)
    user: str
    private_key: SecretStr = Field(
        description="OpenSSH private key; held in memory only, never written to disk."
    )
    host_key_fingerprint: str | None = Field(
        default=None, description="Pinned SSH host key (SHA256:...). Unknown on the first scan."
    )


class AgentRun(_Model):
    """One agent to run in this job, with the effective (merged org/host/site) settings."""

    name: str
    version: int = Field(ge=1)
    site: str | None = Field(default=None, description="Site name for site-scoped agents.")
    settings: dict[str, Any] = Field(default_factory=dict)
    use_claude: bool = True
    review_all: bool = Field(
        default=False,
        description="A deep review (the planner, M7c): Claude reviews all facts, as on a baseline, instead "
        "of only what changed. The diff and change events are still computed.",
    )
    review_sites: list[str] = Field(
        default_factory=list, description="With review_all on a site agent: only these sites (empty = all)."
    )
    review_reason: str | None = Field(default=None, max_length=500, description="Why (from the plan).")


class PreviousSnapshot(_Model):
    agent_version: int
    facts: dict[str, Any]
    taken_at: datetime


class RunOptions(_Model):
    """How much Claude this job may use. The control plane decides from the organization's and host's daily
    budgets; `verify` is off in control-plane scans (verification is its own job, M5c)."""

    use_claude: bool = False
    claude_budget_usd: float = Field(default=0.0, ge=0)
    baseline_review: bool = Field(
        default=True, description="Review all facts when an agent has no comparable previous snapshot."
    )
    verify: bool = Field(default=True, description="Run the verifier on medium+ findings.")


class OpenFinding(_Model):
    """A finding still open in the control plane: agents reuse its kind/subject when it is still present."""

    dedupe_key: str
    agent: str
    site: str | None = None
    title: str
    severity: Severity
    status: str


class ChangeEventRef(_Model):
    """A recent operator or unknown change on the host (context for triage)."""

    kind: str
    agent: str
    site: str | None = None
    summary: str
    observed_at: datetime


class VerifyItem(_Model):
    """A claim for the verifier: what the specialist reported and its evidence, not its reasoning."""

    finding_id: str
    dedupe_key: str
    agent: str
    site: str | None = None
    severity: Severity
    title: str
    evidence: list[str] = Field(default_factory=list)


class VerifyInput(_Model):
    findings: list[VerifyItem] = Field(min_length=1)
    facts: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
        description="Latest facts per reporting agent, keyed `agent` or `agent@site` (the verifier's "
        "observed_facts come from these).",
    )


class FindingVerdict(_Model):
    status: str = Field(description="confirmed, rejected, needs_more or error")
    reason: str | None = None
    checked: list[str] = Field(default_factory=list)
    verifier_version: int | None = None
    at: datetime | None = None


class FindingTriage(_Model):
    severity: Severity
    action: str = Field(description="alert, digest or none")
    reason: str


class FindingRef(_Model):
    """A stored finding as the control plane sends it to triage and compose."""

    finding_id: str
    dedupe_key: str
    host: str
    agent: str
    site: str | None = None
    severity: Severity
    title: str
    summary: str
    evidence: list[str] = Field(default_factory=list)
    recommended_action: str | None = None
    status: str
    first_seen_at: datetime
    last_seen_at: datetime
    verification: FindingVerdict | None = None
    triage: FindingTriage | None = None


class RelatedFinding(_Model):
    """Another active finding in the organization (for linking: same campaign across hosts)."""

    dedupe_key: str
    host: str
    agent: str
    site: str | None = None
    severity: Severity
    title: str
    first_seen_at: datetime


class TaskChain(_Model):
    """Where this task sits in its chain (SPEC §4.2): follow-ups are only accepted while depth < max_depth."""

    depth: int = Field(ge=0)
    max_depth: int = Field(ge=0)
    earlier_questions: list[str] = Field(
        default_factory=list, description="Follow-up questions already asked in this chain (no repeats)."
    )


class TriageInput(_Model):
    findings: list[FindingRef] = Field(min_length=1)
    related: list[RelatedFinding] = Field(default_factory=list)
    change_events: list[ChangeEventRef] = Field(default_factory=list)
    chain: TaskChain


class ComposeRequest(_Model):
    alert_id: str
    kind: str = Field(description="alert (one finding, send now) or digest (several, daily)")
    organization: str
    unverified: bool = Field(
        default=False, description="A critical sent before verification finished (SPEC §9 fallback)."
    )
    findings: list[FindingRef] = Field(min_length=1)


class WatchdogIssueRef(_Model):
    """A watchdog issue (a problem with handscheck itself) for the explain job."""

    issue_id: str
    kind: str
    scope: str
    title: str
    detail: dict[str, Any] = Field(default_factory=dict)
    first_seen_at: datetime
    last_seen_at: datetime


class ExplainInput(_Model):
    """`explain` jobs: write the watchdog's alert for the handscheck team (not customers)."""

    message_id: str
    heading: str = Field(description="e.g. New problem, Still open")
    issues: list[WatchdogIssueRef] = Field(min_length=1)


class ComposeInput(_Model):
    messages: list[ComposeRequest] = Field(min_length=1)


class InvestigateInput(_Model):
    question: str = Field(max_length=2000)
    reason: str = Field(max_length=500)
    finding: RelatedFinding | None = Field(default=None, description="The finding this follows up, if any.")
    open_findings: list[OpenFinding] = Field(default_factory=list)
    facts: dict[str, dict[str, Any]] = Field(
        default_factory=dict, description="Latest facts per agent, keyed `agent` or `agent@site`."
    )


class SettingChange(_Model):
    """A per-host agent setting change: turn an agent on or off, and/or override some of its settings."""

    agent: str
    enabled: bool | None = Field(default=None, description="null = leave as is.")
    settings: dict[str, Any] = Field(default_factory=dict, description="Overrides, valid for the agent.")
    reason: str = Field(max_length=500)


class HostAgentState(_Model):
    """What the control plane already stores for one agent on this host."""

    agent: str
    enabled: bool = True
    settings: dict[str, Any] = Field(default_factory=dict)


class ReconInput(_Model):
    """`recon` jobs (M7c): map the host and propose agent settings. Uses Claude when `options.use_claude`."""

    sites: list[str] = Field(default_factory=list, description="The host's known sites.")
    facts: dict[str, dict[str, Any]] = Field(
        default_factory=dict, description="Latest facts per agent, keyed `agent` or `agent@site`."
    )
    current: list[HostAgentState] = Field(
        default_factory=list, description="The host's stored agent settings (only agents that differ)."
    )


class PlanAgent(_Model):
    """An agent the host runs, with its stored overrides (the planner may only add depth)."""

    name: str
    scope: str
    settings: dict[str, Any] = Field(default_factory=dict)


class PlanInput(_Model):
    """`plan` jobs (M7c): the planner decides how deeply the next scan looks. No host access."""

    host: str
    signals: list[str] = Field(min_length=1, description="Why a plan was asked for (computed by code).")
    agents: list[PlanAgent] = Field(min_length=1)
    sites: list[str] = Field(default_factory=list)
    open_findings: list[OpenFinding] = Field(default_factory=list)
    change_events: list[ChangeEventRef] = Field(default_factory=list)
    profile: str | None = Field(default=None, description="The host's accepted recon profile.")
    max_deep: int = Field(ge=0, description="At most this many deep items.")


class FixProposal(_Model):
    """A fix the worker can apply after a person approves it (M6). Built by code from an action template
    and its parameters; Claude never writes commands. The approval pins `plan_sha256` (action, version,
    params)."""

    action: str = Field(description="Action template, e.g. disable_indexes, neutralize_wp_admin.")
    action_version: int = Field(ge=1)
    params: dict[str, Any]
    summary: str = Field(max_length=500, description="What the fix does, in one or two sentences.")
    risk: str = Field(description="low, medium or high")
    commands: list[str] = Field(description="Every command the fix may run on the host (preview).")
    rollback: list[str] = Field(default_factory=list, description="What undoing it runs (preview).")
    verify: list[str] = Field(default_factory=list, description="How the result is checked afterwards.")
    notes: list[str] = Field(default_factory=list, description="Limits, e.g. what rollback can't restore.")
    plan_sha256: str = Field(pattern="^[0-9a-f]{64}$")


class Approval(_Model):
    user: str = Field(description="Who approved (email).")
    approved_at: datetime


class RemediateInput(_Model):
    proposal_id: str
    mode: str = Field(description="apply or rollback")
    fix: FixProposal
    approval: Approval
    sites: list[str] = Field(default_factory=list, description="The host's sites, for the HTTP baseline.")
    rollback_data: dict[str, Any] | None = Field(
        default=None, description="What the apply step saved (rollback mode only)."
    )


class Job(_Model):
    contract_version: int = CONTRACT_VERSION
    job_id: str
    task_id: str
    kind: JobKind
    host: HostTarget | None = Field(
        default=None,
        description="How to reach the host: required for scan and investigate; optional for verify (no "
        "read-only tool without it); absent for triage and compose.",
    )
    agents: list[AgentRun] = Field(
        default_factory=list,
        description="Agents to run (scan). A site-scoped agent with site=null runs on every discovered site.",
    )
    previous_snapshots: dict[str, PreviousSnapshot] = Field(
        default_factory=dict,
        description="Last snapshot per agent, keyed `agent` or `agent@site`, used to compute the diff.",
    )
    disabled_sites: list[str] = Field(default_factory=list, description="Sites not to scan.")
    open_findings: list[OpenFinding] = Field(default_factory=list)
    options: RunOptions = Field(default_factory=RunOptions)
    suppressions: list[str] = Field(default_factory=list, description="dedupe_key patterns to suppress.")
    verify: VerifyInput | None = None
    triage: TriageInput | None = None
    compose: ComposeInput | None = None
    explain: ExplainInput | None = None
    investigate: InvestigateInput | None = None
    remediate: RemediateInput | None = None
    recon: ReconInput | None = None
    plan: PlanInput | None = None
    deadline: datetime

    @model_validator(mode="after")
    def _inputs_match_kind(self) -> Self:
        sections = {
            JobKind.verify: self.verify,
            JobKind.triage: self.triage,
            JobKind.compose: self.compose,
            JobKind.explain: self.explain,
            JobKind.investigate: self.investigate,
            JobKind.remediate: self.remediate,
            JobKind.recon: self.recon,
            JobKind.plan: self.plan,
        }
        for kind, section in sections.items():
            if (section is not None) != (self.kind == kind):
                raise ValueError(f"the `{kind}` section is required for, and only for, {kind} jobs")
        if (
            self.kind in (JobKind.scan, JobKind.investigate, JobKind.remediate, JobKind.recon)
            and self.host is None
        ):
            raise ValueError(f"{self.kind} jobs need `host`")
        return self


class Snapshot(_Model):
    agent: str
    agent_version: int
    site: str | None = None
    facts: dict[str, Any]


class ChangeEvent(_Model):
    """Operator changes (reboot, package install, config edit, new site): not findings by default."""

    kind: str
    agent: str
    site: str | None = None
    summary: str
    detail: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime


class FindingVerification(_Model):
    status: str = Field(description="pending, confirmed, rejected, needs_more, not_required or error")
    reason: str | None = None
    verifier_version: int | None = None


class Finding(_Model):
    dedupe_key: str = Field(description="Stable key, e.g. malware:php_in_uploads:<host>:<site>:<path>.")
    agent: str
    agent_version: int
    site: str | None = None
    severity: Severity
    title: str
    summary: str
    evidence: list[str] = Field(
        default_factory=list, description="Redacted evidence lines or S3 object refs."
    )
    rule_ids: list[str] = Field(default_factory=list)
    recommended_action: str | None = None
    confidence: str | None = None
    verification: FindingVerification | None = None
    fix: FixProposal | None = Field(
        default=None, description="A fix to propose once the finding is confirmed."
    )
    supersedes: list[str] = Field(
        default_factory=list,
        max_length=100,
        description="Dedupe keys of open findings this one replaces (same agent and site); the control plane "
        "resolves them, e.g. per-folder listing findings folded into one for the site.",
    )


class Metric(_Model):
    name: str
    value: float
    site: str | None = None
    unit: str | None = None


class AgentReview(_Model):
    """One Claude review in the run. After a `baseline` review without error, open findings of that agent and
    site that were not reported again are resolved by the control plane."""

    agent: str
    site: str | None = None
    mode: str = Field(
        description="baseline, deep (the planner's full review; doesn't resolve absent findings), changes or "
        "skipped"
    )
    error: str | None = None


class VerifyVerdict(_Model):
    """The verifier's answer for one finding of a verify job."""

    finding_id: str
    status: str = Field(description="confirmed, rejected, needs_more or error")
    reason: str
    checked: list[str] = Field(default_factory=list)
    verifier_version: int


class FollowUp(_Model):
    """A follow-up task triage asks for. The control plane enforces depth, budget and no repeats."""

    kind: str = Field(description="investigate")
    question: str = Field(max_length=2000)
    reason: str = Field(max_length=500)


class TriageDecision(_Model):
    finding_id: str
    severity: Severity = Field(description="Final severity.")
    action: str = Field(description="alert (now), digest (daily) or none (reports only)")
    reason: str
    related: list[str] = Field(default_factory=list, description="dedupe_keys of related findings.")
    follow_ups: list[FollowUp] = Field(default_factory=list)


class ComposedMessage(_Model):
    alert_id: str
    subject: str = Field(max_length=200)
    body: str = Field(max_length=8000, description="Plain text (light Markdown), used for email and Slack.")


class Investigation(_Model):
    answer: str


class ReconOutput(_Model):
    """What recon found and proposes. Every change was validated against the agent's settings schema."""

    profile: str = Field(max_length=2000, description="A short description of the host.")
    inventory: dict[str, Any] = Field(default_factory=dict, description="What the read-only inventory saw.")
    changes: list[SettingChange] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    model: str | None = Field(default=None, description="The Claude model used; null = code only.")


class PlanItem(_Model):
    agent: str
    site: str | None = None
    depth: str = Field(description="normal or deep (deep = Claude reviews all facts)")
    settings: dict[str, Any] = Field(default_factory=dict, description="Overrides for this run only.")
    reason: str = Field(max_length=500)


class RunPlan(_Model):
    summary: str = Field(max_length=1000)
    items: list[PlanItem] = Field(default_factory=list)


class RemediationStep(_Model):
    phase: str = Field(description="precheck, apply, verify or rollback")
    command: str
    exit_status: int | None = None
    output_sha256: str
    duration_s: float = 0.0


class SiteStatus(_Model):
    site: str
    status: int | None = None
    error: str | None = None


class RemediationOutcome(_Model):
    status: str = Field(description="succeeded, failed, stale, rolled_back or refused")
    message: str = Field(max_length=2000)
    steps: list[RemediationStep] = Field(default_factory=list)
    baseline_before: list[SiteStatus] = Field(default_factory=list)
    baseline_after: list[SiteStatus] = Field(default_factory=list)
    problems: list[str] = Field(default_factory=list, description="What verification found wrong.")
    rollback_data: dict[str, Any] = Field(default_factory=dict, description="Kept for a later rollback.")


class ResultStatus(StrEnum):
    ok = "ok"
    partial = "partial"
    failed = "failed"


class Result(_Model):
    contract_version: int = CONTRACT_VERSION
    job_id: str
    worker_version: str
    status: ResultStatus
    started_at: datetime
    finished_at: datetime
    snapshots: list[Snapshot] = Field(default_factory=list)
    change_events: list[ChangeEvent] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    metrics: list[Metric] = Field(default_factory=list)
    reviews: list[AgentReview] = Field(default_factory=list)
    verdicts: list[VerifyVerdict] = Field(default_factory=list, description="verify jobs")
    triage: list[TriageDecision] = Field(default_factory=list, description="triage jobs")
    messages: list[ComposedMessage] = Field(
        default_factory=list,
        description="compose jobs (alert_id = the alert) and explain jobs (alert_id = the message_id)",
    )
    investigation: Investigation | None = Field(default=None, description="investigate jobs")
    remediation: RemediationOutcome | None = Field(default=None, description="remediate jobs")
    recon: ReconOutput | None = Field(default=None, description="recon jobs")
    plan: RunPlan | None = Field(default=None, description="plan jobs")
    errors: list[str] = Field(default_factory=list)
    host_key_fingerprint: str | None = Field(
        default=None, description="The host key seen on this run (SHA256:...), pinned on the first scan."
    )
    claude_input_tokens: int = 0
    claude_output_tokens: int = 0
    claude_cost_usd: float = 0.0


class AgentCatalogEntry(_Model):
    name: str
    title: str
    description: str
    version: int = Field(ge=1)
    scope: str = Field(pattern="^(host|site|org)$")
    cadence: str
    watch: bool = Field(
        default=False, description="Also runs in the watch pass (every 15-60 min, rules only)."
    )
    model: str | None = None
    settings_schema: dict[str, Any] = Field(default_factory=dict)


class Catalog(_Model):
    contract_version: int = CONTRACT_VERSION
    worker_version: str
    agents: list[AgentCatalogEntry]
