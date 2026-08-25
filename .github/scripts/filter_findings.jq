# Filter CodeMender findings against pull request commit.diff and construct dynamic matrix.
#
# Usage:
#   # With explicit diff file (legacy/external):
#   jq --rawfile diff commit.diff [--argjson max_findings 10] -f github-actions/scripts/filter_findings.jq findings.json
#   # With native find-diff payload (diff filtering already applied):
#   jq [--argjson max_findings 10] -f github-actions/scripts/filter_findings.jq findings.json

def severity_rank:
  (if type == "string" then ascii_upcase else "" end) as $s |
  if $s == "CRITICAL" then 4
  elif $s == "HIGH" then 3
  elif $s == "MEDIUM" then 2
  elif $s == "LOW" then 1
  else 0
  end;

def parse_diff($diff_text):
  (($diff_text // "") | split("\n")) as $lines
  | reduce $lines[] as $line (
      {current_file: null, ranges: []};
      if ($line | startswith("+++ b/")) then
        .current_file = ($line | sub("^\\+\\+\\+ b/"; ""))
      elif ($line | startswith("diff --git a/")) then
        # fallback file path detection if +++ b/ is absent
        ($line | capture("diff --git a/.+ b/(?<path>.+)$")) as $cap
        | .current_file = $cap.path
      elif ($line | startswith("@@ ")) and .current_file != null then
        ($line | capture("@@ -[0-9]+(,[0-9]+)? \\+(?<start>[0-9]+)(,(?<count>[0-9]+))? @@.*")) as $cap
        | ($cap.start | tonumber) as $start
        | (if $cap.count then ($cap.count | tonumber) else 1 end) as $count
        | (if $count == 0 then $start else ($start + $count - 1) end) as $end
        | .ranges += [{
            file: .current_file,
            start: $start,
            end: $end
          }]
      else
        .
      end
    )
  | .ranges;

($ARGS.named.diff // null) as $raw_diff
| (if $raw_diff != null then parse_diff($raw_diff) else null end) as $ranges
| ($ARGS.named.mode // "in_diff") as $mode
| (if . == null then [] else . end)
| map(
    . as $finding
    | (($finding.FilePath // $finding.file_path // "") | sub("^/workspace/?"; "") | sub("^\\./"; "") | sub("^/"; "")) as $fp
    | ($finding.StartLine // $finding.line // 1) as $f_start
    | ($finding.EndLine // $finding.end_line // $f_start) as $f_end
    | select(
        if $ranges == null then
          ($mode != "preexisting")
        else
          ($ranges | any(
            (.file | sub("^\\./"; "") | sub("^/"; "")) == $fp and
            $f_start <= .end and
            $f_end >= .start
          )) as $in_diff
          | if $mode == "preexisting" then
              ($in_diff | not)
            else
              $in_diff
            end
        end
      )
  )

| sort_by(-((.Severity // .severity // "") | severity_rank))
| (($ARGS.named.max // $ARGS.named.max_findings // null) as $limit
   | if $limit != null and ($limit | type == "number") and $limit >= 0 then
       .[0:$limit]
     else
       .
     end
  )
| map({
    finding_id: (.FindingID // .finding_id // ""),
    file_path: (.FilePath // .file_path // ""),
    start_line: (.StartLine // .line // 1),
    severity: (.Severity // .severity // "UNKNOWN"),
    title: (.Title // .title // ""),
    payload: .
  })
