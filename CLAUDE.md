# Spam Mail Filter Research — Project Instructions

## Key Files

| File | Purpose |
|---|---|
| `spam_analyzer.py` | Main Python script — parses Junk mbox, builds origin clusters, generates filter rules |
| `run_spam_analyzer.bat` | Batch launcher — copies Junk mbox, runs analyzer, installs .dat to Thunderbird profile |
| `msgFilterRules.dat` | Generated Thunderbird filter rules (output — installed to Thunderbird profile) |
| `thunderbird_rules.txt` | Human-readable cluster report (output) |
| `README.md` | Project readme and usage guide |
| `Spam Filter Claude Plan.txt` | Planning notes for the filter system |
| `Junk` | Thunderbird Junk/Spam mbox file — source data, copied from profile by the batch file |

## Technical Notes

**Thunderbird version:** 151.0.1. Custom header filter conditions must use quoted lowercase header names:
`condition="OR (\"x-sender-ip\",contains,value)"` — raw header names without quotes are silently ignored.

**IMAP trash folder:** The user's Spam/Junk folder is displayed as "Spam" in Thunderbird's UI but the underlying IMAP file is named `Junk`. The trash folder is displayed as "Trash" but its IMAP name is `Deleted`. The correct `_TRASH_URI` is:
`imap://REDACTED%40EXAMPLE.COM@outlook.office365.com/Deleted`

**Custom header registration:** All custom headers used in filter conditions must be registered in `mailnews.customHeaders` in `prefs.js`. Current registered headers include `DKIM-Signature`, `Return-Path`, `Received-SPF`, `X-Sender-IP`, `X-SID-PRA`, `Authentication-Results`, and others.

**Manual rule preservation:** `generate_dat()` calls `_read_preserved_rules()` which reads the currently installed `.dat` from the Thunderbird profile and retains any rules whose name does not start with `"Spam - "`. This ensures manually created Thunderbird filters survive script re-runs.

**Rule duplication bug (fixed):** `_read_preserved_rules()` originally split the installed `.dat` into rule blocks using blank lines as separators. Thunderbird sometimes rewrites the file without blank lines between filters (e.g. after the user opens/edits Message Filters in the UI), which caused hundreds of rules to get lumped into a single block. Since only the *first* rule's name in a block was checked against the `"Spam - "` prefix, an entire multi-hundred-rule block could be misclassified as "manual" and preserved wholesale, then a fresh set appended on top — causing the rule count to balloon every run (observed: 237 → 943 rules). Fixed by splitting blocks on each `name=` line instead of blank lines, so every rule is preserved/discarded individually regardless of the installed file's blank-line formatting.

**Expected rule count behavior:** Each run fully replaces the `"Spam - "` rule set based on whatever is currently in the Junk mbox — it does not accumulate across runs. Rule counts will rise and fall naturally with how much spam has collected in Junk since the last run (clustering requires >= `DAT_MIN_EMAILS` messages from >= 2 distinct senders sharing an origin). Avoid emptying the Junk folder immediately before running the analyzer, since that removes the volume needed to form clusters and will temporarily shrink rule coverage.
