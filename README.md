# Spam Origin Analyzer for Thunderbird

Analyzes a Thunderbird Junk/Spam mailbox and generates Thunderbird filter rules from two complementary angles:

- **Technical origin** — groups emails that share the same sending infrastructure (IP address, DKIM signing domain, HELO hostname, bounce-path domain, etc.) even when they appear to come from completely different senders and subjects
- **Subject and sender name** — groups emails that reuse the same subject line or display name across multiple different email addresses

Produces two outputs: a human-readable cluster report (`thunderbird_rules.txt`) and a ready-to-install Thunderbird filter rules file (`msgFilterRules.dat`).

---

## The Problem It Solves

Spam campaigns disguise their origin by rotating From addresses, subject lines, and apparent sending domains with each message. The underlying sending infrastructure — IP addresses, DKIM signing domains, HELO hostnames, bounce-path domains — often stays the same. This tool finds those hidden technical fingerprints and groups emails by common origin.

A second class of spam doesn't bother rotating infrastructure but does rotate email addresses. These campaigns reuse the same display name (e.g. "TrimRX Weight Loss") or identical subject lines across many different sending addresses. The script catches these too by clustering on subject and sender name.

---

## Requirements

- Python 3.x (no third-party packages — uses only the standard library)
- A Thunderbird `Junk` mailbox file copied into the same folder as the script

---

## One-Time Configuration

Before the first run, open `spam_analyzer.py` in a text editor and update these three constants near the top of the file to match your Thunderbird setup:

```python
_PROFILE = r'C:\Users\YourName\AppData\Roaming\Thunderbird\Profiles\xxxxxxxx.default-release'
_ACCOUNT = r'ImapMail\your.mail.server.com'
_TRASH_URI = 'imap://youraddress%40example.com@your.mail.server.com/Deleted'
```

`_TRASH_URI` must be an **IMAP folder URI**, not a local mailbox path. For most Outlook/Hotmail accounts the trash folder is named `Deleted` on the server (displayed as "Trash" in Thunderbird's UI). For Gmail accounts it is `[Gmail]/Trash`. To find the exact URI: in Thunderbird open **Tools → Message Filters**, create a temporary filter with action "Move to folder", select your Trash folder, save it, close Thunderbird, and inspect the `actionValue=` line in your account's `msgFilterRules.dat`.

To find your profile path in Thunderbird: **Help → Troubleshooting Information → Profile Folder → Open Folder**.

The `_ACCOUNT` subfolder is named after your incoming mail server. Look inside `ImapMail\` (for IMAP accounts) or `Mail\` (for POP3 accounts) inside your profile folder.

You can also adjust this threshold (default 5) to control how many rules are generated:

```python
DAT_MIN_EMAILS = 4   # only generate a filter rule for clusters with this many emails or more
```

---

## Setup

1. In Thunderbird, locate your Junk folder file on disk. It is a plain file named `Junk` with no extension, inside your account's subfolder in the Thunderbird profile (e.g. `ImapMail\outlook.office365.com\Junk`).
2. Copy that `Junk` file into the same directory as `spam_analyzer.py`.
3. Run the script.

---

## Automated Run (Batch File)

`run_spam_analyzer.bat` handles the entire workflow in one double-click:

1. Checks that Thunderbird is closed — aborts with an error message if it is running
2. Copies the `Junk` file directly from your Thunderbird profile into the project folder
3. Runs `python spam_analyzer.py`
4. Installs the generated `msgFilterRules.dat` back into the Thunderbird profile

**To use:** close Thunderbird, then double-click `run_spam_analyzer.bat`. When it finishes, start Thunderbird and verify the rules via **Tools → Message Filters**.

You can also run this on a schedule using Windows Task Scheduler. Set it to a time when Thunderbird is normally closed (e.g. 3am weekly). If Thunderbird happens to be open when the task fires, the batch file will abort safely without making any changes.

---

## Manual Usage

```
python spam_analyzer.py
```

The script will:
1. Parse all emails in the `Junk` file (must already be in the project folder)
2. Extract technical headers from each message
3. Group messages into **header clusters** by shared technical origin
4. Group messages into **subject/sender clusters** by identical subject line or display name
5. Print the full cluster report to the console
6. Write `thunderbird_rules.txt` — the full human-readable report (header clusters only)
7. Write `msgFilterRules.dat` — filter rules for all cluster types, ready to install

The final summary line shows all counts, e.g.:
```
msgFilterRules.dat generated: 66 header rules + 78 subject/sender rules
```

---

## What It Analyzes

For each email the script extracts these technical headers:

| Header | What is extracted | Why it matters |
|--------|------------------|----------------|
| `DKIM-Signature` | `d=` signing domain | Cryptographically tied to sender infrastructure; hardest to fake |
| `DomainKey-Signature` | `d=` signing domain | Older DKIM variant, same logic |
| `Return-Path` | Domain after `@` | Bounce-routing address; hard to randomize across a campaign |
| `Authentication-Results` | `smtp.mailfrom`, `header.d` | Mail server's consolidated authentication summary |
| `Received-SPF` | `smtp.mailfrom` domain, `helo` hostname | SPF-verified originating domain and declared server name |
| `Received` | First external IP before internal hops | Actual sending server IP address |
| `X-Sender-IP` | IP address | Outlook/Exchange extracted sender IP |
| `X-SID-PRA` | Domain portion | Sender ID Purported Responsible Address |

Note: "DKIM Signing Domain", "HELO Domain", etc. are labels the script uses internally — they are not actual header names. The actual header names used in the filter rules are listed in the `>> THUNDERBIRD RULE` block of each cluster entry in `thunderbird_rules.txt`.

---

## Subject and Sender Name Analysis

In addition to technical headers, the script generates rules from two content-based patterns:

| Cluster type | What is matched | Thunderbird rule generated |
|---|---|---|
| **Subject** | Emails sharing an identical subject line | `subject contains <subject>` |
| **Sender name** | Emails sharing an identical From display name | `from contains <display name>` |

Subject and sender rules require at least 5 emails from at least 2 different email addresses to qualify.

Both rule types use Thunderbird's built-in `subject` and `from` attributes, which are always cached for IMAP messages. This means **Run Now works instantly** on these rules without fetching full messages from the server.

Generated rule names follow the pattern `Spam - Subject: ...` and `Spam - Sender: ...`.

---

## How Clusters Are Built

**Header clusters** — a group of messages that:
- Share the same value for one of the technical headers listed above, **and**
- Have at least 2 different apparent `From` addresses

The second condition is the key signal: same infrastructure + different disguises = coordinated spam campaign deliberately hiding its origin.

**Subject/sender clusters** — a group of messages that:
- Share an identical subject line (10+ characters) or From display name (5+ characters), **and**
- Have at least 2 different email address domains, **and**
- Total at least `DAT_MIN_EMAILS` (default 5) messages

All clusters are sorted by email count (largest first). Generic header values (`none`, `unknown`, `neutral`, etc.) are excluded to prevent over-broad rules.

---

## Understanding the Report Output

```
[CLUSTER 001]  HELO Domain: 88-97-172-4.dsl.zen.co.uk
  Emails matched : 48       <- total emails from this infrastructure
  Distinct From  : 20       <- how many different From disguises were used
  Sample subjects:
    "A Quick Auto Insurance Quote Check"
    ...
  Sample From addresses:
    allcapitol.com
    ankerzebra.xyz
    ...

  >> THUNDERBIRD RULE
    Custom Header : Received-SPF
    Condition     : contains
    Match Value   : helo=88-97-172-4.dsl.zen.co.uk
```

- **Emails matched** is the total count of emails sharing that infrastructure
- **Distinct From** is how many different apparent senders were used — a high number relative to email count confirms deliberate disguising
- The `>> THUNDERBIRD RULE` block gives the exact values to use when creating a rule manually in Thunderbird's filter dialog

---

## Installing the Filter Rules (Automatic)

The script generates `msgFilterRules.dat` containing rules for all clusters with 5 or more emails.

The batch file (`run_spam_analyzer.bat`) installs the file automatically. It also preserves any filter rules you have created manually in Thunderbird — only rules whose name begins with `Spam - ` are replaced on each run.

Each run fully regenerates the `Spam - ` rule set from whatever is currently in your Junk mailbox — it does not add to what's already installed. Rule counts will rise and fall with how much spam has accumulated since the last run. Avoid emptying the Junk folder immediately before running the analyzer, since clustering needs enough volume (multiple emails from multiple senders sharing an origin) to generate a rule.

**To install manually:**

1. Close Thunderbird completely
2. Copy `msgFilterRules.dat` from the project folder into:
   `[profile]\ImapMail\[account]\msgFilterRules.dat`
3. Restart Thunderbird
4. Go to **Tools → Message Filters** to confirm the rules appear in the list

---

## Creating Rules Manually (Optional)

If you prefer to add individual rules through the Thunderbird UI:

1. Open **Tools → Message Filters → New**
2. Set **Match** to **any of the following**
3. In the condition row:
   - First dropdown: scroll down to **Customize...**, type the Custom Header name (e.g. `X-Sender-IP`), click **Add**
   - Second dropdown: **contains**
   - Text field: paste the Match Value (e.g. `88.97.172.4`)
4. Set the **Action** to your preference
5. Click **OK**

---

## Thunderbird Filter Settings

When creating or reviewing filter rules, set **Getting New Mail** to:

> **Filter after spam classification**

This lets Thunderbird's built-in junk detector run first, then your custom rules act as a second layer catching what the built-in filter missed.

The generated `msgFilterRules.dat` encodes this setting as `type="48"` in each rule entry — the internal value Thunderbird uses for "Getting New Mail / After spam classification." No manual adjustment is needed.

### Running filters on existing mail

To apply the rules to emails already sitting in a folder, go to **Tools → Message Filters**, select the rules you want to run (Ctrl+A to select all), then click **Run Now**. Thunderbird will scan every message in the currently selected folder against the filter conditions.

**Header rules** (`Spam - HELO Domain`, `Spam - X-Sender-IP`, etc.) check non-standard headers that Thunderbird does not cache for IMAP messages. Thunderbird must fetch the full message from the server for each email. On large folders this can take several minutes — be patient and wait for it to finish before checking results.

**Subject and sender rules** (`Spam - Subject`, `Spam - Sender`) use Thunderbird's built-in `subject` and `from` attributes, which are always cached. These run instantly regardless of folder size.

---

## Tips

- **Clusters 001–010** are the highest-priority — they cover the most emails and represent the most active spam campaigns.
- When two consecutive header clusters share the same sample subjects and From addresses (e.g. a HELO cluster and an X-Sender-IP cluster for the same IP), they identify the same sender. One rule is enough.
- **DKIM-based rules** (e.g. `d=firebaseapp.com`) are the most durable — they match any random subdomain the spammer uses on that platform.
- **IP-based rules** (`X-Sender-IP`, `Received`) can become stale if the spammer moves to a new server. Domain and DKIM rules tend to last longer.
- **Subject rules** are highly precise but short-lived — spammers eventually rotate subject lines. **Sender name rules** tend to last longer as brand names (e.g. "TrimRX Weight Loss") are harder to rotate.
- Re-run the script periodically against a refreshed Junk/Spam folder to discover new campaigns and add new rules. Manually created filters in Thunderbird are preserved across re-runs.
