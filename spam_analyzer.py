import mailbox
import re
import os
import sys
from collections import defaultdict
from email.header import decode_header, make_header

# Force UTF-8 output on Windows so the report prints cleanly
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MBOX_PATH   = os.path.join(SCRIPT_DIR, 'Junk')
OUTPUT_PATH = os.path.join(SCRIPT_DIR, 'thunderbird_rules.txt')
DAT_PATH    = os.path.join(SCRIPT_DIR, 'msgFilterRules.dat')

# Thunderbird profile / account details for msgFilterRules.dat generation.
# Personal values live in local_settings.py (gitignored, not committed) —
# see local_settings.example.py for the template.
sys.path.insert(0, SCRIPT_DIR)
import local_settings
_PROFILE = local_settings.PROFILE
_ACCOUNT = local_settings.ACCOUNT
_INSTALL_PATH = os.path.join(_PROFILE, _ACCOUNT, 'msgFilterRules.dat')
_TRASH_URI = local_settings.TRASH_URI
DAT_MIN_EMAILS = 3

# Microsoft/Exchange infrastructure -- skip when finding first external IP
_INTERNAL_RE = re.compile(
    r'outlook\.com|hotmail\.com|microsoft\.com|office365\.com|'
    r'protection\.outlook\.com|prod\.exchangelabs\.com|'
    r'namprd\d+|BL[A-Z0-9]+NAM|SN[A-Z0-9]+NAM|DM[A-Z0-9]+NAM|'
    r'MN[A-Z0-9]+NAM|CO[A-Z0-9]+NAM|CY[A-Z0-9]+NAM|SA[A-Z0-9]+NAM|'
    r'BN[A-Z0-9]+NAM|MW[A-Z0-9]+NAM',
    re.IGNORECASE
)
_PRIVATE_IP_RE = re.compile(
    r'^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)'
)


def _decode(value):
    if not value:
        return ''
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return str(value)


def _extract_email_domain(text):
    m = re.search(r'@([\w.-]+)', str(text))
    return m.group(1).lower() if m else None


def _parse_dkim_domains(value):
    return list({m.strip().rstrip(';').lower()
                 for m in re.findall(r'\bd\s*=\s*([^\s;,]+)', value)})


def _parse_auth_results(value):
    out = {}
    for key, pat in [
        ('smtp.mailfrom', r'smtp\.mailfrom\s*=\s*([^\s;]+)'),
        ('header.from',   r'header\.from\s*=\s*([^\s;]+)'),
        ('header.d',      r'header\.d\s*=\s*([^\s;]+)'),
    ]:
        m = re.search(pat, value, re.IGNORECASE)
        if m:
            v = m.group(1).strip().lower()
            out[key] = v.split('@')[1] if '@' in v else v
    return out


def _parse_received_spf(value):
    out = {}
    for key, pat in [
        ('client-ip',     r'client-ip\s*=\s*([\d.:a-fA-F]+)'),
        ('smtp.mailfrom', r'smtp\.mailfrom\s*=\s*([^\s;)]+)'),
        ('helo',          r'helo\s*=\s*([^\s;)]+)'),
    ]:
        m = re.search(pat, value, re.IGNORECASE)
        if m:
            v = m.group(1).strip().lower()
            if key != 'client-ip' and '@' in v:
                v = v.split('@')[1]
            out[key] = v
    return out


def _first_external_ip(received_list):
    # received_list is newest-first; reverse to get oldest-first (closest to origin)
    for hdr in reversed(received_list):
        if _INTERNAL_RE.search(hdr):
            continue
        m = re.search(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', hdr)
        if m and not _PRIVATE_IP_RE.match(m.group(1)):
            return m.group(1)
    return None


def _extract_from_name(from_raw):
    m = re.match(r'^"?([^"<@\n]+?)"?\s*<', from_raw.strip())
    if m:
        name = m.group(1).strip()
        if len(name) >= 5:
            return name
    return None


# (msg_key, cluster_label, thunderbird_header, thunderbird_match_prefix)
FIELD_CONFIGS = [
    ('dkim_domains',       'DKIM Signing Domain',     'DKIM-Signature',         'd='),
    ('return_path_domain', 'Return-Path Domain',       'Return-Path',            '@'),
    ('smtp_mailfrom',      'smtp.mailfrom Domain',     'Authentication-Results', 'smtp.mailfrom='),
    ('header_d',           'header.d Domain',          'Authentication-Results', 'header.d='),
    ('first_external_ip',  'First External IP',        'Received',               ''),
    ('spf_smtp_mailfrom',  'SPF smtp.mailfrom Domain', 'Received-SPF',           'smtp.mailfrom='),
    ('helo',               'HELO Domain',              'Received-SPF',           'helo='),
    ('x_sender_ip',        'X-Sender-IP',              'X-Sender-IP',            ''),
    ('x_sid_pra_domain',   'X-SID-PRA Domain',         'X-SID-PRA',              ''),
]
LABEL_TO_FC = {fc[1]: fc for fc in FIELD_CONFIGS}


def parse_messages(mbox):
    messages = []
    for i, msg in enumerate(mbox):
        if i % 200 == 0:
            print(f'\r  Parsing... {i}', end='', flush=True)

        info = {
            'index': i,
            'from_raw':  _decode(msg.get('From', '')),
            'from_addr': _extract_email_domain(msg.get('From', '')) or _decode(msg.get('From', '')),
            'subject':   _decode(msg.get('Subject', '')),
            'dkim_domains':       [],
            'return_path_domain': None,
            'smtp_mailfrom':      None,
            'header_d':           None,
            'first_external_ip':  None,
            'spf_smtp_mailfrom':  None,
            'helo':               None,
            'x_sender_ip':        None,
            'x_sid_pra_domain':   None,
        }

        rp = msg.get('Return-Path', '')
        if rp:
            info['return_path_domain'] = _extract_email_domain(rp)

        for sig in (msg.get_all('DKIM-Signature') or []):
            info['dkim_domains'].extend(_parse_dkim_domains(sig))
        for sig in (msg.get_all('DomainKey-Signature') or []):
            info['dkim_domains'].extend(_parse_dkim_domains(sig))
        info['dkim_domains'] = list(set(info['dkim_domains']))

        auth = msg.get('Authentication-Results', '')
        if auth:
            ar = _parse_auth_results(auth)
            info['smtp_mailfrom'] = ar.get('smtp.mailfrom')
            info['header_d']      = ar.get('header.d')

        spf = msg.get('Received-SPF', '')
        if spf:
            sr = _parse_received_spf(spf)
            info['spf_smtp_mailfrom'] = sr.get('smtp.mailfrom')
            info['helo']              = sr.get('helo')

        info['first_external_ip'] = _first_external_ip(msg.get_all('Received') or [])

        xip = msg.get('X-Sender-IP', '')
        info['x_sender_ip'] = xip.strip() if xip else None

        sid = msg.get('X-SID-PRA', '')
        info['x_sid_pra_domain'] = _extract_email_domain(sid) if sid else None

        messages.append(info)

    print(f'\r  Parsed {len(messages)} messages.          ')
    return messages


# Generic/meaningless values that would create over-broad filter rules
_SKIP_VALUES = {'none', 'unknown', 'neutral', 'temperror', 'permerror', ''}


def build_clusters(messages):
    raw = defaultdict(set)
    for idx, msg in enumerate(messages):
        for fc in FIELD_CONFIGS:
            field_key, label = fc[0], fc[1]
            val = msg[field_key]
            if not val:
                continue
            if isinstance(val, list):
                for v in val:
                    if v and v.lower() not in _SKIP_VALUES:
                        raw[(label, v)].add(idx)
            else:
                if val.lower() not in _SKIP_VALUES:
                    raw[(label, val)].add(idx)

    meaningful = []
    for (label, value), indices in raw.items():
        from_addrs = {messages[i]['from_addr'] for i in indices}
        if len(indices) >= 2 and len(from_addrs) >= 2:
            meaningful.append((label, value, indices, from_addrs))

    meaningful.sort(key=lambda x: len(x[2]), reverse=True)
    return meaningful


def build_subject_sender_clusters(messages):
    subject_groups = defaultdict(set)
    sender_groups  = defaultdict(set)

    for idx, msg in enumerate(messages):
        subj = msg['subject'].strip()
        if len(subj) >= 10 and '"' not in subj:
            subject_groups[subj].add(idx)

        name = _extract_from_name(msg['from_raw'])
        if name and '"' not in name:
            sender_groups[name].add(idx)

    clusters = []
    for subj, indices in subject_groups.items():
        from_addrs = {messages[i]['from_addr'] for i in indices}
        if len(indices) >= DAT_MIN_EMAILS and len(from_addrs) >= 2:
            clusters.append(('Subject', subj, indices, from_addrs))

    for name, indices in sender_groups.items():
        from_addrs = {messages[i]['from_addr'] for i in indices}
        if len(indices) >= DAT_MIN_EMAILS and len(from_addrs) >= 2:
            clusters.append(('Sender', name, indices, from_addrs))

    clusters.sort(key=lambda x: len(x[2]), reverse=True)
    return clusters


def format_report(messages, clusters):
    W = 72
    lines = []

    lines += [
        '=' * W,
        'SPAM ORIGIN CLUSTERS  -  Thunderbird Filter Rule Targets',
        '=' * W,
        f'Total emails analyzed : {len(messages)}',
        f'Meaningful clusters   : {len(clusters)}',
        '',
        'HOW TO USE IN THUNDERBIRD',
        '  Tools -> Message Filters -> New',
        '  Set "Match" to "any of the following"',
        '  Add a condition: Custom Header -> [Header] -> contains -> [Match Value]',
        '  Action: move to Junk / delete / mark as junk -- your choice',
        '',
    ]

    for n, (label, value, indices, from_addrs) in enumerate(clusters, 1):
        fc = LABEL_TO_FC.get(label)
        tb_header = fc[2] if fc else label
        tb_prefix = fc[3] if fc else ''
        tb_match  = f'{tb_prefix}{value}'

        sample_subj = sorted({messages[i]['subject'] for i in indices})[:3]
        sample_from = sorted(from_addrs)[:5]

        lines += [
            f'[CLUSTER {n:03d}]  {label}: {value}',
            f'  Emails matched : {len(indices)}',
            f'  Distinct From  : {len(from_addrs)}  <- different disguises, same origin',
            '  Sample subjects:',
        ]
        for s in sample_subj:
            lines.append(f'    "{s[:75]}"')
        lines.append('  Sample From addresses:')
        for f_ in sample_from:
            lines.append(f'    {f_[:75]}')
        lines += [
            '',
            '  >> THUNDERBIRD RULE',
            f'    Custom Header : {tb_header}',
            f'    Condition     : contains',
            f'    Match Value   : {tb_match}',
            '',
        ]

    lines += [
        '=' * W,
        'QUICK-REFERENCE TABLE',
        '=' * W,
        f'{"Custom Header":<36} {"Match Value":<36} {"Emails":>6}',
        '-' * W,
    ]
    for label, value, indices, _ in clusters:
        fc = LABEL_TO_FC.get(label)
        tb_header = fc[2] if fc else label
        tb_prefix = fc[3] if fc else ''
        tb_match  = f'{tb_prefix}{value}'
        lines.append(f'{tb_header:<36} {tb_match:<36} {len(indices):>6}')

    return '\n'.join(lines)


def _read_preserved_rules():
    """Return rule blocks from the installed .dat that are not generated spam rules."""
    if not os.path.exists(_INSTALL_PATH):
        return []
    try:
        with open(_INSTALL_PATH, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception:
        return []
    # Split into per-rule blocks using 'name=' as the boundary rather than
    # blank lines: Thunderbird sometimes rewrites the .dat without blank
    # lines between filters, which previously caused many rules to be
    # lumped into a single block and preserved/discarded together.
    blocks, current = [], []
    for line in content.splitlines():
        if line.startswith('version=') or line.startswith('logging='):
            continue
        if line == '':
            continue
        if line.startswith('name='):
            if current:
                blocks.append(current)
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append(current)
    preserved = []
    for block in blocks:
        if not block[0][6:-1].startswith('Spam - '):
            preserved.append(block)
    return preserved


def generate_dat(clusters, subject_sender_clusters=None):
    significant = [(l, v, idx, fa) for l, v, idx, fa in clusters
                   if len(idx) >= DAT_MIN_EMAILS]

    lines = ['version="9"', 'logging="no"']

    for block in _read_preserved_rules():
        lines.extend(block)
        lines.append('')

    for label, value, indices, _ in significant:
        fc = LABEL_TO_FC.get(label)
        tb_header = fc[2] if fc else label
        tb_prefix = fc[3] if fc else ''
        tb_match  = f'{tb_prefix}{value}'

        name = f'Spam - {label}: {value}'[:60].replace('"', '').replace('\n', '')

        lines += [
            f'name="{name}"',
            'enabled="yes"',
            'type="48"',
            'action="Move to folder"',
            f'actionValue="{_TRASH_URI}"',
            f'condition="OR (\\"{tb_header.lower()}\\",contains,{tb_match})"',
            '',
        ]

    ss_count = 0
    for label, value, indices, _ in (subject_sender_clusters or []):
        tb_attr = 'subject' if label == 'Subject' else 'from'
        name = f'Spam - {label}: {value}'[:60].replace('"', '').replace('\n', '')
        lines += [
            f'name="{name}"',
            'enabled="yes"',
            'type="48"',
            'action="Move to folder"',
            f'actionValue="{_TRASH_URI}"',
            f'condition="OR ({tb_attr},contains,{value})"',
            '',
        ]
        ss_count += 1

    with open(DAT_PATH, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    return len(significant), ss_count


def main():
    print(f'Loading {MBOX_PATH} ...')
    mbox = mailbox.mbox(MBOX_PATH)
    messages = parse_messages(mbox)
    print('Building clusters...')
    clusters = build_clusters(messages)
    print(f'Found {len(clusters)} meaningful clusters.\n')

    report = format_report(messages, clusters)
    print(report)
    with open(OUTPUT_PATH, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f'\nReport written to:\n  {OUTPUT_PATH}')

    ss_clusters = build_subject_sender_clusters(messages)
    print(f'Subject/Sender clusters : {len(ss_clusters)}')

    n_hdr, n_ss = generate_dat(clusters, ss_clusters)
    print(f'\nmsgFilterRules.dat generated: {n_hdr} header rules + {n_ss} subject/sender rules')
    print(f'  Written to: {DAT_PATH}')
    print(f'\nTO INSTALL IN THUNDERBIRD:')
    print(f'  1. Close Thunderbird completely')
    print(f'  2. Check if this file already exists:')
    print(f'     {_INSTALL_PATH}')
    print(f'     - If NOT: copy msgFilterRules.dat directly to that folder')
    print(f'     - If YES: open both files in a text editor and paste the rules')
    print(f'       from the generated file after the first two lines of the existing one')
    print(f'  3. Restart Thunderbird')
    print(f'  4. Verify via Tools -> Message Filters (rules should appear in the list)')


if __name__ == '__main__':
    main()
