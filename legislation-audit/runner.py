"""One-time public legislative access audit, intended for a fresh hosted runner.

No state credentials, persistent browser profile, stealth plugins, or paid APIs.
Only compact counts, hashes and outcomes are printed; Virginia's CSV is not saved.
"""
import csv
import hashlib
import io
import json
import os
import pathlib
import platform
import re
import subprocess
import sys
import time
import traceback
from datetime import datetime, timezone
from urllib.parse import urlparse

from pypdf import PdfReader
from playwright.sync_api import sync_playwright

OUT = pathlib.Path('audit-results')
OUT.mkdir(exist_ok=True)
RESULT = {
    'schema': 1,
    'started_at': datetime.now(timezone.utc).isoformat(),
    'runtime': {k: os.environ.get(k) for k in [
        'GITHUB_ACTIONS', 'GITHUB_REPOSITORY', 'GITHUB_RUN_ID',
        'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA', 'RUNNER_ENVIRONMENT',
        'RUNNER_OS', 'ImageOS', 'ImageVersion']},
    'platform': platform.platform(),
    'credentials': 'No state accounts, state API keys, or saved browser state supplied',
    'checks': [],
}


def record(name, fn):
    start = time.monotonic()
    row = {'name': name, 'started_at': datetime.now(timezone.utc).isoformat()}
    try:
        row.update(fn() or {})
        row['pass'] = True
    except Exception as exc:
        row.update({'pass': False, 'error': str(exc)[:4000]})
    row['seconds'] = round(time.monotonic() - start, 2)
    RESULT['checks'].append(row)
    print('CHECK ' + json.dumps(row), flush=True)
    (OUT / 'result.json').write_text(json.dumps(RESULT, indent=2))


def fingerprint(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def curl(url, extra=()):
    # A separate process, with no browser cookies, HTTP authentication or API key.
    target = OUT / 'temporary-response'
    proc = subprocess.run([
        'curl', '--silent', '--show-error', '--location', '--connect-timeout', '20',
        '--max-time', '65', '--max-filesize', '20000000',
        '--user-agent', 'PublicLegislationAccessAudit/1.0',
        '--output', str(target), '--write-out', '%{http_code}\n%{content_type}\n%{url_effective}',
        *extra, url], capture_output=True, text=True, timeout=70)
    fields = proc.stdout.strip().split('\n')
    data = target.read_bytes() if target.exists() else b''
    target.unlink(missing_ok=True)
    meta = {'url': url, 'status': fields[0] if fields else None,
            'mime': fields[1] if len(fields) > 1 else None, **fingerprint(data)}
    assert proc.returncode == 0, f'curl {proc.returncode}: {proc.stderr}; {meta}'
    assert meta['status'] in ['200', '206', '226'], meta
    return data, meta


def pdf(data, expected):
    assert data.startswith(b'%PDF-'), f'Not a PDF; first bytes: {data[:100]!r}'
    doc = PdfReader(io.BytesIO(data))
    text = '\n'.join(p.extract_text() or '' for p in doc.pages)
    assert len(text.strip()) > 300, 'PDF lacks substantive extractable text'
    assert re.search(expected, text, re.I), 'Expected bill identity not found in PDF'
    return {**fingerprint(data), 'pages': len(doc.pages), 'text_chars': len(text),
            'identity_pattern': expected, 'identity_verified': True}


def ct_ftp():
    data, meta = curl('ftp://ftp.cga.ct.gov/pub/data/bill_info.csv')
    rows = list(csv.reader(io.StringIO(data.decode('utf-8-sig', errors='replace'))))
    assert len(rows) > 100, 'FTP payload is not a substantive inventory'
    return {**meta, 'csv_rows_including_header': len(rows), 'first_row_columns': len(rows[0])}


def tx_ftp():
    root, meta = curl('ftp://ftp.legis.state.tx.us/bills/')
    sessions = sorted(set(re.findall(r'\b(?:8[89]|90)(?:R|\d)\b', root.decode(errors='replace'))))
    assert '90R' in sessions and '89R' in sessions, sessions
    samples = []
    for chamber, group, filename in [
        ('house_bills', 'HB00100_HB00199', 'HB00101I.htm'),
        ('senate_bills', 'SB00001_SB00099', 'SB00031I.htm')]:
        directory = f'ftp://ftp.legis.state.tx.us/bills/90R/billtext/html/{chamber}/{group}/'
        listing, listing_meta = curl(directory)
        assert filename in listing.decode(errors='replace'), 'Introduced file missing from directory'
        data, text_meta = curl(directory + filename)
        text = re.sub('<[^>]+>', ' ', data.decode(errors='replace'))
        assert len(text.strip()) > 1000 and re.search(r'BE IT ENACTED', text, re.I), 'Not bill full text'
        samples.append({**text_meta, 'introduced_suffix_verified': True, 'text_chars': len(text),
                        'directory_listing': listing_meta})
    return {**meta, 'sessions_observed': sessions, 'samples': samples}


def virginia_csv():
    data, meta = curl('https://lis.blob.core.windows.net/lisfiles/20261/BILLS.CSV')
    rows = list(csv.DictReader(io.StringIO(data.decode('utf-8-sig', errors='replace'))))
    assert len(rows) > 1000, 'Truncated or invalid inventory'
    return {**meta, 'records': len(rows), 'columns': list(rows[0]),
            'raw_csv_retained_or_published': False}


def california_range():
    data, meta = curl('https://downloads.leginfo.legislature.ca.gov/pubinfo_2025.zip', ['--range', '0-1023'])
    assert meta['status'] == '206' and data.startswith(b'PK') and len(data) == 1024, meta
    return {**meta, 'scope': 'Cloud range transport only; full XML extraction covered by separate audit'}


def federal_xml():
    import xml.etree.ElementTree as ET
    url = 'https://www.govinfo.gov/bulkdata/BILLS/119/2/hr/BILLS-119hr11033ih.xml'
    data, meta = curl(url)
    root = ET.fromstring(data)
    text = ''.join(root.itertext())
    assert len(text) > 500 and root.attrib.get('bill-stage') == 'Introduced-in-House', root.attrib
    return {**meta, 'xml_root': root.tag, 'attributes': root.attrib, 'text_chars': len(text)}


def browser_checks():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        RESULT['browser'] = {'engine': 'chromium', 'version': browser.version, 'headless': True,
                             'fresh_context': True, 'saved_profile': False}
        context = browser.new_context(accept_downloads=True)
        page = context.new_page()
        page.set_default_timeout(45000)

        def indiana_inventory():
            url = 'https://iga.in.gov/legislative/2026/bills'
            resp = page.goto(url, wait_until='domcontentloaded', timeout=65000)
            page.wait_for_selector('a[href*="/2026/bills/house/"]')
            # Wait until the same nonempty ID set has been observed three times.
            previous, stable = [], 0
            for _ in range(30):
                links = page.locator('a[href]').evaluate_all('(xs) => xs.map(x => x.href)')
                ids = sorted(set(re.findall(r'/2026/bills/(house|senate)/(\d+)', '\n'.join(links))))
                stable = stable + 1 if ids == previous else 0
                if stable >= 3:
                    break
                previous = ids
                page.wait_for_timeout(1000)
            counts = {ch: sum(1 for x in ids if x[0] == ch) for ch in ['house', 'senate']}
            assert counts['house'] >= 452 and counts['senate'] >= 290, counts
            return {'url': url, 'status': resp.status, 'records': len(ids), 'chambers': counts,
                    'inventory_sha256': hashlib.sha256(json.dumps(ids).encode()).hexdigest(),
                    'no_login_or_approval_requested': True}

        def indiana_pdf(chamber, number, code, pattern):
            detail = f'https://iga.in.gov/legislative/2026/bills/{chamber}/{number}/details'
            page.goto(detail, wait_until='domcontentloaded', timeout=65000)
            # Use the public UI's versions expander and its introduced-document link.
            page.get_by_text('Bill Versions', exact=True).click()
            introduced = page.get_by_text(re.compile(r'1\.\s+Introduced .* Bill')).first
            introduced.click()
            locator = page.locator(f'a[href*="/{code}/{code}.01.INTR.pdf"]').first
            locator.wait_for(state='attached')
            url = locator.get_attribute('href')
            if url.startswith('/'):
                url = 'https://iga.in.gov' + url
            # The browser's anonymous request context follows the link with the same site context.
            response = context.request.get(url, timeout=65000)
            data = response.body()
            if not data.startswith(b'%PDF-'):
                # Some hosts distinguish ordinary requests from a browser link download.
                with page.expect_download(timeout=65000) as download:
                    locator.click()
                data = pathlib.Path(download.value.path()).read_bytes()
            return {'detail_url': detail, 'text_url': url, 'http_status': response.status,
                    'version': '01.INTR', **pdf(data, pattern)}

        def virginia_browser(bill, pattern, session='20261'):
            url = f'https://lis.virginia.gov/bill-details/{session}/{bill}/text/{bill}'
            page.goto(url, wait_until='domcontentloaded', timeout=65000)
            link = page.get_by_role('link', name='PDF', exact=True)
            link.wait_for()
            body = page.locator('body').inner_text()
            assert len(body) > 1500 and re.search(pattern, body, re.I), 'Missing rendered bill text'
            target = link.get_attribute('href')
            response = context.request.get(target, timeout=65000)
            data = response.body()
            return {'url': url, 'rendered_chars': len(body), 'pdf_url': target,
                    'pdf_http_status': response.status, **pdf(data, pattern)}

        record('IN anonymous browser inventory', indiana_inventory)
        record('IN House introduced PDF', lambda: indiana_pdf('house', 1001, 'HB1001', r'HOUSE BILL No\.\s*1001'))
        record('IN Senate introduced PDF', lambda: indiana_pdf('senate', 1, 'SB0001', r'SENATE BILL No\.\s*1\b'))
        record('VA House public browser and PDF', lambda: virginia_browser('HB1', r'HOUSE BILL NO\.\s*1\b'))
        record('VA Senate public browser and PDF', lambda: virginia_browser('SB1', r'SENATE BILL NO\.\s*1\b'))
        record('VA special-session Senate introduced PDF', lambda: virginia_browser('SB4001', r'SENATE BILL NO\.\s*4001\b', '20262'))
        record('VA 2027 House prefile introduced PDF', lambda: virginia_browser('HB1532', r'HOUSE BILL NO\.\s*1532\b', '20271'))
        record('VA 2027 Senate prefile introduced PDF', lambda: virginia_browser('SB837', r'SENATE BILL NO\.\s*837\b', '20271'))
        context.close()
        browser.close()


record('CT anonymous FTP inventory', ct_ftp)
record('TX anonymous FTP inventory and introduced text', tx_ftp)
record('VA anonymous complete CSV', virginia_csv)
record('CA anonymous ZIP range transport', california_range)
record('Federal introduced XML control', federal_xml)
try:
    browser_checks()
except Exception as exc:
    RESULT['checks'].append({'name': 'Browser initialization', 'pass': False, 'error': str(exc)})
RESULT['finished_at'] = datetime.now(timezone.utc).isoformat()
RESULT['passed'] = sum(r['pass'] for r in RESULT['checks'])
RESULT['failed'] = sum(not r['pass'] for r in RESULT['checks'])
(OUT / 'result.json').write_text(json.dumps(RESULT, indent=2))
print('AUDIT_RESULT_BEGIN\n' + json.dumps(RESULT, indent=2) + '\nAUDIT_RESULT_END', flush=True)
sys.exit(1 if RESULT['failed'] else 0)

