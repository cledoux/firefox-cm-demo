#!/usr/bin/env python3
"""
publish_comments.py

Translates CodeMender ChangeEnvelope records into GitHub PR inline review suggestions
with 1-click apply diff blocks, catches HTTP 422 errors on out-of-diff lines with issue
comment fallback, and appends finding summary cards to $GITHUB_STEP_SUMMARY.

Governing: ADR-0004, ADR-0005, SPEC-workflow/cm-pr-workflow, REQ-0006, REQ-0007, REQ-TEST.2
"""

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple


def format_review_comment_body(envelope: Dict[str, Any], hunk: Dict[str, Any]) -> str:
    """Formats an inline pull request review comment with ```suggestion markdown block.
    // Governing: ADR-0005, SPEC-workflow/cm-pr-workflow, REQ-0006
    """
    title = envelope.get("title") or "Security Finding"
    vuln_type = envelope.get("vuln_type") or "Vulnerability"
    severity = envelope.get("severity") or "HIGH"
    summary = envelope.get("summary") or "CodeMender automated remediation."
    replacement = (hunk.get("replacement") or "").rstrip("\n")

    return (
        f"### 🛡️ CodeMender Auto-Fix: {title}\n"
        f"> **Vulnerability:** {vuln_type} | **Severity:** {severity}\n\n"
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
    count = len(findings)
    header = (
        "### 🛡️ CodeMender Advisory: Potentially Preexisting Security Finding(s) (Non-Blocking)\n"
        "> **Note:** The following finding(s) were detected in untouched sections of the codebase "
        "outside the current pull request diff. They are advisory and do not block this PR.\n\n"
    )
    items = []
    for idx, item in enumerate(findings, 1):
        payload = item.get("payload") or item
        title = item.get("title") or payload.get("Title") or "Untitled Security Finding"
        vuln_type = payload.get("VulnType") or payload.get("vuln_type") or "Vulnerability"
        severity = item.get("severity") or payload.get("Severity") or "UNKNOWN"
        fp = item.get("file_path") or payload.get("FilePath") or payload.get("file_path") or "unknown"
        line = item.get("start_line") or payload.get("StartLine") or payload.get("line") or 1
        analysis = payload.get("Analysis") or payload.get("analysis") or payload.get("message") or "No details available."

        items.append(
            f"#### {idx}. {title}\n"
            f"- **File:** `{fp}:{line}`\n"
            f"- **Severity:** `{severity}` | **Vulnerability:** `{vuln_type}`\n"
            f"- **Details:** {analysis}\n"
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
    """CLI entrypoint for standalone execution."""
    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: python3 publish_comments.py [--advisory] <change_envelope.json | preexisting_findings.json>", file=sys.stdout)
        print("Translates ChangeEnvelope JSON into PR review comments or posts advisory preexisting finding comments.")
        sys.exit(0)

    if "--advisory" in sys.argv:
        args = [a for a in sys.argv[1:] if a != "--advisory"]
        target_file = args[0] if len(args) > 0 else os.environ.get("FINDINGS_PATH")
        if not target_file:
            print("Usage: python3 publish_comments.py --advisory <preexisting_findings.json>", file=sys.stderr)
            sys.exit(1)
        try:
            with open(target_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            findings = data if isinstance(data, list) else [data]
            result = publish_advisory_findings(findings=findings)
            print(json.dumps(result, indent=2))
        except Exception as exc:
            print(f"[ERROR] publish_advisory_findings failed: {exc}", file=sys.stderr)
            sys.exit(1)
        return

    if len(sys.argv) < 2 and not os.environ.get("ENVELOPE_PATH"):
        print("Usage: python3 publish_comments.py <change_envelope.json>", file=sys.stderr)
        sys.exit(1)

    envelope_file = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ENVELOPE_PATH")
    try:
        result = publish_comments(envelope_path=envelope_file)
        print(json.dumps(result, indent=2))
    except Exception as exc:
        print(f"[ERROR] publish_comments failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

