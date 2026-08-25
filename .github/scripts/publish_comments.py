#!/usr/bin/env python3
"""
publish_comments.py

Translates CodeMender ChangeEnvelope and Finding records into GitHub PR inline review suggestions
and executive scan summary reports. Supports two-tier commenting architecture:
- Summary Mode (--mode=summary): Ingests findings.json and posts a comprehensive executive summary issue comment with findings table and collapsible threat analysis.
- Inline Mode (--mode=inline, default): Ingests change_envelope.json and publishes lightweight 1-click apply review suggestions.
- Advisory Mode (--advisory): Ingests out-of-diff findings and posts non-blocking advisory notes.

Governing: ADR-0004, ADR-0005, SPEC-workflow/cm-pr-workflow, REQ-0006, REQ-0007, REQ-TEST.2
"""

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


def normalize_finding(item: Dict[str, Any]) -> Dict[str, Any]:
    """Polymorphically extracts finding attributes supporting PascalCase and snake_case."""
    payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}

    finding_id = (
        item.get("finding_id")
        or item.get("FindingID")
        or item.get("id")
        or payload.get("FindingID")
        or payload.get("finding_id")
        or ""
    )
    title = (
        item.get("title")
        or item.get("Title")
        or payload.get("Title")
        or payload.get("title")
        or "Security Finding"
    )
    vuln_type = (
        item.get("vuln_type")
        or item.get("VulnType")
        or payload.get("VulnType")
        or payload.get("vuln_type")
        or "Vulnerability"
    )
    severity = (
        item.get("severity")
        or item.get("Severity")
        or payload.get("Severity")
        or payload.get("severity")
        or "UNKNOWN"
    ).upper()
    status = (
        item.get("status")
        or item.get("Status")
        or payload.get("Status")
        or payload.get("status")
        or "DETECTED"
    ).upper()
    file_path = (
        item.get("file_path")
        or item.get("FilePath")
        or payload.get("FilePath")
        or payload.get("file_path")
        or "unknown"
    )
    start_line_raw = (
        item.get("start_line")
        or item.get("StartLine")
        or payload.get("StartLine")
        or payload.get("start_line")
        or item.get("line")
        or 1
    )
    try:
        start_line = int(start_line_raw)
    except (ValueError, TypeError):
        start_line = 1

    analysis = (
        item.get("analysis")
        or item.get("Analysis")
        or payload.get("Analysis")
        or payload.get("analysis")
        or item.get("message")
        or payload.get("message")
        or "No detailed analysis available."
    )

    return {
        "finding_id": finding_id,
        "title": title,
        "vuln_type": vuln_type,
        "severity": severity,
        "status": status,
        "file_path": file_path,
        "start_line": start_line,
        "analysis": analysis,
    }


def format_executive_summary(findings: List[Dict[str, Any]]) -> str:
    """Formats an executive Markdown summary with metrics, findings table, and collapsible threat analysis."""
    normalized = [normalize_finding(f) for f in findings]
    total = len(normalized)

    sev_counts: Dict[str, int] = {}
    for f in normalized:
        sev = f["severity"]
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    sev_summary_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        if sev in sev_counts:
            sev_summary_parts.append(f"**{sev}:** {sev_counts[sev]}")
    sev_summary_str = " | ".join(sev_summary_parts) if sev_summary_parts else "None"

    header = (
        "### 🛡️ CodeMender Security Scan Summary\n\n"
        f"**Total Findings:** {total} ({sev_summary_str})\n\n"
    )

    table_header = (
        "| Severity | Status | Finding | Location | Action |\n"
        "|---|---|---|---|---|\n"
    )
    table_rows = []
    for f in normalized:
        sev = f["severity"]
        status = f["status"]
        title = f["title"]
        vuln = f["vuln_type"]
        loc = f"`{f['file_path']}:{f['start_line']}`"
        action = "Automated Fix Pending" if status in ["DETECTED", "PENDING", "OPEN"] else ("Remediated" if status == "FIXED" else "Review Required")
        table_rows.append(f"| `{sev}` | `{status}` | **{title}** (`{vuln}`) | {loc} | {action} |")

    table_str = table_header + "\n".join(table_rows) + "\n\n"

    details_header = "<details><summary><b>🔍 View Vulnerability & Threat Analysis</b></summary>\n\n"
    details_body = []
    for idx, f in enumerate(normalized, 1):
        details_body.append(
            f"#### {idx}. {f['title']} (`{f['vuln_type']}`)\n"
            f"- **Location:** `{f['file_path']}:{f['start_line']}`\n"
            f"- **Severity:** `{f['severity']}` | **Status:** `{f['status']}`\n"
            f"- **Threat Analysis & Impact:**\n\n"
            f"{f['analysis']}\n"
        )
    details_str = details_header + "\n".join(details_body) + "\n</details>\n"

    return header + table_str + details_str


def publish_summary(
    findings: Optional[Any] = None,
    findings_path: Optional[str] = None,
    api_url: Optional[str] = None,
    repo: Optional[str] = None,
    pr_number: Optional[int] = None,
    token: Optional[str] = None,
    summary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Publishes executive summary comment and step summary in summary mode."""
    data = findings
    if data is None:
        target_file = findings_path or os.environ.get("FINDINGS_PATH")
        if not target_file:
            raise ValueError("publish_summary: No findings data or file path provided.")
        if not os.path.exists(target_file):
            raise FileNotFoundError(f"publish_summary: Findings file not found at {target_file}")
        with open(target_file, "r", encoding="utf-8") as f:
            data = json.load(f)

    findings_list = data if isinstance(data, list) else [data]
    if not findings_list:
        return {"status": "NO_FINDINGS", "issue_comments_posted": 0}

    base_api_url = (api_url or os.environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
    repository = repo or os.environ.get("GITHUB_REPOSITORY") or ""
    auth_token = token or os.environ.get("GITHUB_TOKEN") or ""

    pr_num = pr_number
    if pr_num is None:
        pr_env = os.environ.get("PR_NUMBER")
        if pr_env and pr_env.isdigit():
            pr_num = int(pr_env)
        else:
            pr_num = 0

    issue_endpoint = f"{base_api_url}/repos/{repository}/issues/{pr_num}/comments"
    issue_comments_posted = 0

    summary_markdown = format_executive_summary(findings_list)
    if auth_token and repository and pr_num:
        try:
            _send_github_api_request(issue_endpoint, auth_token, {"body": summary_markdown})
            issue_comments_posted += 1
            print(f"[INFO] Posted executive scan summary comment for {len(findings_list)} finding(s).", file=sys.stderr)
        except Exception as err:
            print(f"[WARN] Failed to post scan summary issue comment: {err}", file=sys.stderr)

    target_path = summary_path or os.environ.get("GITHUB_STEP_SUMMARY")
    if target_path:
        with open(target_path, "a", encoding="utf-8") as f:
            f.write(summary_markdown + "\n")

    return {
        "status": "SUMMARY_POSTED",
        "findings_count": len(findings_list),
        "issue_comments_posted": issue_comments_posted,
    }


def format_review_comment_body(envelope: Dict[str, Any], hunk: Dict[str, Any]) -> str:
    """Formats a lightweight inline pull request review comment with ```suggestion markdown block.
    // Governing: ADR-0005, SPEC-workflow/cm-pr-workflow, REQ-0006
    """
    title = envelope.get("title") or "Security Finding"
    summary = envelope.get("summary") or "CodeMender automated remediation."
    replacement = (hunk.get("replacement") or "").rstrip("\n")

    return (
        f"### 🛡️ CodeMender Fix: {title}\n\n"
        f"{summary}\n\n"
        f"```suggestion\n"
        f"{replacement}\n"
        f"```"
    )


def format_fallback_issue_comment_body(
    envelope: Dict[str, Any], hunk: Optional[Dict[str, Any]] = None
) -> str:
    """Formats a fallback top-level issue comment when review comment fails with HTTP 422.
    // Governing: ADR-0005, SPEC-workflow/cm-pr-workflow, REQ-0007
    """
    title = envelope.get("title") or "Security Finding"
    vuln_type = envelope.get("vuln_type") or "Vulnerability"
    severity = envelope.get("severity") or "HIGH"
    summary = envelope.get("summary") or "CodeMender automated remediation."

    files_modified = envelope.get("files_modified") or []
    file_path = (hunk and hunk.get("file_path")) or (files_modified[0] if files_modified else "target file")
    line_info = f":{hunk['start_line']}" if (hunk and hunk.get("start_line")) else ""

    patch_content = envelope.get("patch") or ""
    if not patch_content and hunk and hunk.get("original"):
        orig = hunk["original"] if hunk["original"].endswith("\n") else hunk["original"] + "\n"
        repl = hunk.get("replacement") or ""
        patch_content = f"--- a/{file_path}\n+++ b/{file_path}\n-{orig}+{repl}"

    return (
        f"### 🛡️ CodeMender Security Finding (Outside PR Diff): {title}\n"
        f"**File:** `{file_path}{line_info}` | **Severity:** {severity} | **Vulnerability:** {vuln_type}\n\n"
        f"{summary}\n\n"
        f"```diff\n"
        f"{patch_content.strip()}\n"
        f"```"
    )


def format_advisory_issue_comment_body(findings: List[Dict[str, Any]]) -> str:
    """Formats an advisory top-level issue comment for potentially preexisting findings outside PR diff.
    // Governing: ADR-0005, SPEC-workflow/cm-pr-workflow, REQ-0004, REQ-0007
    """
    header = (
        "### 🛡️ CodeMender Advisory: Potentially Preexisting Security Finding(s) (Non-Blocking)\n"
        "> **Note:** The following finding(s) were detected in untouched sections of the codebase "
        "outside the current pull request diff. They are advisory and do not block this PR.\n\n"
    )
    items = []
    for idx, item in enumerate(findings, 1):
        f = normalize_finding(item)
        items.append(
            f"#### {idx}. {f['title']}\n"
            f"- **File:** `{f['file_path']}:{f['start_line']}`\n"
            f"- **Severity:** `{f['severity']}` | **Vulnerability:** `{f['vuln_type']}`\n"
            f"- **Details:** {f['analysis']}\n"
        )
    return header + "\n".join(items)


def publish_advisory_findings(
    findings: List[Dict[str, Any]],
    api_url: Optional[str] = None,
    repo: Optional[str] = None,
    pr_number: Optional[int] = None,
    token: Optional[str] = None,
    summary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Publishes non-blocking advisory comments and step summaries for out-of-diff findings.
    // Governing: ADR-0005, SPEC-workflow/cm-pr-workflow, REQ-0004, REQ-0007
    """
    if not findings:
        return {"status": "NO_PREEXISTING_FINDINGS", "issue_comments_posted": 0}

    base_api_url = (api_url or os.environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
    repository = repo or os.environ.get("GITHUB_REPOSITORY") or ""
    auth_token = token or os.environ.get("GITHUB_TOKEN") or ""

    pr_num = pr_number
    if pr_num is None:
        pr_env = os.environ.get("PR_NUMBER")
        if pr_env and pr_env.isdigit():
            pr_num = int(pr_env)
        else:
            pr_num = 0

    issue_endpoint = f"{base_api_url}/repos/{repository}/issues/{pr_num}/comments"
    issue_comments_posted = 0

    body = format_advisory_issue_comment_body(findings)
    if auth_token and repository and pr_num:
        try:
            _send_github_api_request(issue_endpoint, auth_token, {"body": body})
            issue_comments_posted += 1
            print(f"[INFO] Posted advisory comment for {len(findings)} potentially preexisting finding(s).", file=sys.stderr)
        except Exception as err:
            print(f"[WARN] Failed to post advisory issue comment: {err}", file=sys.stderr)

    target_path = summary_path or os.environ.get("GITHUB_STEP_SUMMARY")
    if target_path:
        with open(target_path, "a", encoding="utf-8") as f:
            f.write(body + "\n")

    return {
        "status": "ADVISORY_POSTED",
        "findings_count": len(findings),
        "issue_comments_posted": issue_comments_posted,
    }


def format_summary_card(envelope: Dict[str, Any], summary_path: Optional[str] = None) -> None:
    """Writes or appends a remediation summary card to $GITHUB_STEP_SUMMARY.
    // Governing: ADR-0005, SPEC-workflow/cm-pr-workflow, REQ-0006, REQ-0007
    """
    target_path = summary_path or os.environ.get("GITHUB_STEP_SUMMARY")
    if not target_path:
        return

    title = envelope.get("title") or "Security Finding"
    vuln_type = envelope.get("vuln_type") or "Vulnerability"
    severity = envelope.get("severity") or "UNKNOWN"
    status = envelope.get("status") or "UNKNOWN"
    summary = envelope.get("summary") or "No remediation details provided."

    files_modified_list = envelope.get("files_modified") or []
    if files_modified_list:
        files_modified = ", ".join(f"`{f}`" for f in files_modified_list)
    else:
        files_modified = "None"

    card = (
        "### 🛡️ CodeMender Remediation Summary\n\n"
        f"**Finding:** {title} (`{vuln_type}`)\n\n"
        f"**Severity:** `{severity}` | **Status:** `{status}`\n\n"
        f"**Files Modified:** {files_modified}\n\n"
        f"> {summary}\n\n"
    )

    with open(target_path, "a", encoding="utf-8") as f:
        f.write(card)


def _send_github_api_request(
    url: str, token: str, payload: Dict[str, Any]
) -> Tuple[int, Dict[str, Any]]:
    """Sends a JSON POST request to the GitHub REST API using urllib."""
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "CodeMender-PR-Workflow/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        body = resp.read().decode("utf-8")
        return resp.status, json.loads(body) if body else {}


def publish_comments(
    envelope: Optional[Dict[str, Any]] = None,
    envelope_path: Optional[str] = None,
    api_url: Optional[str] = None,
    repo: Optional[str] = None,
    pr_number: Optional[int] = None,
    commit_sha: Optional[str] = None,
    token: Optional[str] = None,
    summary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Main publisher entrypoint for translating ChangeEnvelope to PR review comments.
    // Governing: ADR-0004, ADR-0005, SPEC-workflow/cm-pr-workflow, REQ-0006, REQ-0007, REQ-TEST.2
    """
    env_data = envelope

    # Load envelope from path if not provided in memory
    if not env_data:
        target_file = envelope_path or os.environ.get("ENVELOPE_PATH")
        if not target_file:
            raise ValueError("publish_comments: No ChangeEnvelope object or file path provided.")
        if not os.path.exists(target_file):
            raise FileNotFoundError(f"publish_comments: ChangeEnvelope file not found at {target_file}")
        with open(target_file, "r", encoding="utf-8") as f:
            env_data = json.load(f)

    # Handle UNRESOLVED or empty patch findings
    hunks = env_data.get("hunks") or []
    patch = env_data.get("patch") or ""
    if env_data.get("status") == "UNRESOLVED" or (not patch and not hunks):
        print(
            f"[INFO] Finding {env_data.get('finding_id', '')} ({env_data.get('title', 'Untitled')}) is UNRESOLVED. Skipping review comments.",
            file=sys.stderr,
        )
        format_summary_card(env_data, summary_path)
        return {
            "status": "UNRESOLVED",
            "review_comments_posted": 0,
            "issue_comments_posted": 0,
        }

    # Resolve environment and API configurations
    base_api_url = (api_url or os.environ.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
    repository = repo or os.environ.get("GITHUB_REPOSITORY") or ""
    auth_token = token or os.environ.get("GITHUB_TOKEN") or ""

    pr_num = pr_number
    if pr_num is None:
        pr_env = os.environ.get("PR_NUMBER")
        if pr_env and pr_env.isdigit():
            pr_num = int(pr_env)
        else:
            pr_num = 0

    head_sha = commit_sha or os.environ.get("COMMIT_SHA") or ""

    review_comments_posted = 0
    issue_comments_posted = 0
    fallback_posted = False

    review_endpoint = f"{base_api_url}/repos/{repository}/pulls/{pr_num}/comments"
    issue_endpoint = f"{base_api_url}/repos/{repository}/issues/{pr_num}/comments"

    # If status is FIXED but hunks array is empty and patch is non-empty, post top-level fallback
    if not hunks and patch:
        if auth_token and repository and pr_num:
            fallback_body = format_fallback_issue_comment_body(env_data)
            _send_github_api_request(
                issue_endpoint,
                auth_token,
                {"body": fallback_body},
            )
            issue_comments_posted += 1
            fallback_posted = True

    # Process individual hunks
    for hunk in hunks:
        body = format_review_comment_body(env_data, hunk)
        start_line = hunk.get("start_line")
        end_line = hunk.get("end_line") or start_line or 1
        is_single_line = not start_line or start_line == end_line

        params: Dict[str, Any] = {
            "body": body,
            "commit_id": head_sha,
            "path": hunk.get("file_path", ""),
            "line": end_line,
            "side": "RIGHT",
        }

        # Multi-line comment coordinates per REQ-0006.4
        if not is_single_line:
            params["start_line"] = start_line
            params["start_side"] = "RIGHT"

        try:
            if auth_token and repository and pr_num:
                _send_github_api_request(review_endpoint, auth_token, params)
                review_comments_posted += 1
                print(f"[INFO] Posted inline suggestion on {hunk.get('file_path')}:{end_line}", file=sys.stderr)
        except urllib.error.HTTPError as err:
            if err.code == 422:
                print(
                    f"[INFO] Line outside diff for {hunk.get('file_path')}:{end_line} (HTTP 422). Falling back to issue comment.",
                    file=sys.stderr,
                )
                if auth_token and repository and pr_num and not fallback_posted:
                    fallback_body = format_fallback_issue_comment_body(env_data, hunk)
                    _send_github_api_request(
                        issue_endpoint,
                        auth_token,
                        {"body": fallback_body},
                    )
                    issue_comments_posted += 1
                    fallback_posted = True
            else:
                print(f"[ERROR] Failed to publish review comment: {err}", file=sys.stderr)
                raise

    # Write step summary card
    format_summary_card(env_data, summary_path)

    return {
        "status": "FIXED",
        "review_comments_posted": review_comments_posted,
        "issue_comments_posted": issue_comments_posted,
    }


def main() -> None:
    """CLI entrypoint supporting --mode=summary, --mode=inline, and --advisory."""
    if "-h" in sys.argv or "--help" in sys.argv:
        print(
            "Usage: python3 publish_comments.py [--mode=summary|--mode=inline|--advisory] <file.json>",
            file=sys.stdout,
        )
        print("Translates ChangeEnvelope JSON into PR review comments or publishes finding summaries.")
        sys.exit(0)

    mode = "inline"
    args = sys.argv[1:]
    clean_args = []

    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("--mode="):
            mode = arg.split("=", 1)[1].lower()
        elif arg == "--mode" and i + 1 < len(args):
            mode = args[i + 1].lower()
            i += 1
        elif arg == "--advisory":
            mode = "advisory"
        else:
            clean_args.append(arg)
        i += 1

    target_file = clean_args[0] if clean_args else (
        os.environ.get("FINDINGS_PATH") if mode in ["summary", "advisory"] else os.environ.get("ENVELOPE_PATH")
    )

    if not target_file and not (mode == "inline" and os.environ.get("ENVELOPE_PATH")):
        print(f"Usage: python3 publish_comments.py [--mode={mode}] <file.json>", file=sys.stderr)
        sys.exit(1)

    try:
        if mode == "summary":
            result = publish_summary(findings_path=target_file)
        elif mode == "advisory":
            with open(target_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            findings = data if isinstance(data, list) else [data]
            result = publish_advisory_findings(findings=findings)
        else:  # inline (default)
            result = publish_comments(envelope_path=target_file)

        print(json.dumps(result, indent=2))
    except Exception as exc:
        print(f"[ERROR] publish_comments failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()


