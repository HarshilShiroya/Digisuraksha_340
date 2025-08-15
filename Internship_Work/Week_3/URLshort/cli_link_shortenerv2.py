#!/usr/bin/env python3
"""
CLI Link Shortener v2

This file is an updated single-file CLI + Flask shortener implementing:
 - Atomic one-time redirects (safe against race conditions)
 - Code generation modes: numeric (1,2,3...), hash (base62), random (secure random string)
 - CLI flags: --mode {numeric,hash,random} and --random-length
 - A 'help' subcommand with detailed usage examples

Run the server:
  python cli_link_shortener_v2.py serve --host 0.0.0.0 --port 8080

Shorten a URL (default numeric mode -> /1):
  python cli_link_shortener_v2.py shorten --url "https://example.com" --api http://127.0.0.1:8080/api/shorten

Shorten with hash mode (obfuscated):
  python cli_link_shortener_v2.py shorten --url "https://example.com" --mode hash --api http://127.0.0.1:8080/api/shorten

Shorten with random code (unpredictable):
  python cli_link_shortener_v2.py shorten --url "https://example.com" --mode random --random-length 8 --api http://127.0.0.1:8080/api/shorten

Features included:
 - One-time links (auto-expire after single successful click)
 - Expiring links (by seconds / absolute time)
 - Max-clicks limit
 - Optional password-protection (provide pw via ?pw=... or header X-LINK-PW)
 - Automatic page title fetch and store (link preview)
 - QR-code returned as data URL (if `qrcode` library installed)
 - Batch shorten CSV (input file) via CLI
 - Simple analytics endpoint for clicks and last-click time

Dependencies:
 - Python 3.8+
 - pip install flask requests
 - Optional: pip install qrcode[pil] (for QR code images)

This file contains both the server and the CLI client. No GUI.

(See full help with: python cli_link_shortener_v2.py help)
"""

import os
import re
import io
import time
import json
import sqlite3
import string
import hashlib
import argparse
import base64
import secrets
from datetime import datetime

from flask import Flask, request, jsonify, redirect, abort, Response

try:
    import requests
except Exception:
    raise SystemExit('Please install requests: pip install requests')

# optional qrcode
try:
    import qrcode
    _HAS_QR = True
except Exception:
    _HAS_QR = False

DB = os.environ.get('SHORT_DB', 'shorty.db')
ALPHABET = string.digits + string.ascii_letters
BASE = len(ALPHABET)

app = Flask(__name__)

# ----------------------------- helpers -----------------------------

def encode_base62(n):
    if n == 0:
        return ALPHABET[0]
    s = []
    while n:
        s.append(ALPHABET[n % BASE])
        n //= BASE
    return ''.join(reversed(s))


def now_ts():
    return int(time.time())


def db_conn():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db_conn()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS urls(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE,
            original_url TEXT NOT NULL,
            created_at INTEGER,
            expire_at INTEGER,
            max_clicks INTEGER DEFAULT NULL,
            clicks INTEGER DEFAULT 0,
            password_hash TEXT DEFAULT NULL,
            one_time INTEGER DEFAULT 0,
            title TEXT DEFAULT NULL
        )
    ''')
    conn.commit()
    conn.close()


# Basic URL validation to avoid internal addresses (simple)
_BLOCKED_NETS = [
    re.compile(r'^https?://localhost', re.I),
    re.compile(r'^https?://127\.'),
    re.compile(r'^https?://10\.'),
    re.compile(r'^https?://192\.168\.'),
    re.compile(r'^https?://172\.(1[6-9]|2[0-9]|3[0-1])\.'),
]


def is_allowed_url(url):
    for p in _BLOCKED_NETS:
        if p.search(url):
            return False
    return True


def hash_pw(pw: str):
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()


# fetch title (best-effort)
_TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.I | re.S)

def fetch_title(url):
    try:
        h = {'User-Agent': 'shortener-bot/1.0'}
        r = requests.get(url, headers=h, timeout=5, allow_redirects=True)
        if r.status_code == 200 and r.text:
            m = _TITLE_RE.search(r.text)
            if m:
                title = re.sub(r'\s+', ' ', m.group(1)).strip()
                return title[:250]
    except Exception:
        return None
    return None


def make_qr_dataurl(text):
    if not _HAS_QR:
        return None
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    b64 = base64.b64encode(buf.getvalue()).decode('ascii')
    return f'data:image/png;base64,{b64}'


def make_random_code(length=6):
    return ''.join(secrets.choice(ALPHABET) for _ in range(length))


# ----------------------------- Flask API -----------------------------

@app.route('/api/shorten', methods=['POST'])
def api_shorten():
    data = request.json or {}
    original = data.get('url')
    custom_code = data.get('custom_code')
    expire_seconds = data.get('expire_seconds')
    max_clicks = data.get('max_clicks')
    password = data.get('password')
    one_time = bool(data.get('one_time'))
    want_qr = bool(data.get('qr', False))

    # New: select code mode. Accepts 'numeric'(default), 'hash', 'random'
    code_mode = data.get('code_mode', 'numeric')
    random_length = int(data.get('random_length') or 6)

    if not original:
        return jsonify({'error': 'url required'}), 400

    if not (original.startswith('http://') or original.startswith('https://')):
        return jsonify({'error': 'url must start with http:// or https://'}), 400

    if not is_allowed_url(original):
        return jsonify({'error': 'url not allowed (blocked or internal)'}), 400

    conn = db_conn()
    cur = conn.cursor()

    title = fetch_title(original)

    expire_at = None
    if expire_seconds:
        try:
            expire_at = now_ts() + int(expire_seconds)
        except Exception:
            expire_at = None

    pw_hash = None
    if password:
        pw_hash = hash_pw(password)

    if custom_code:
        try:
            cur.execute('INSERT INTO urls(code, original_url, created_at, expire_at, max_clicks, password_hash, one_time, title) VALUES (?,?,?,?,?,?,?,?)',
                        (custom_code, original, now_ts(), expire_at, max_clicks, pw_hash, int(one_time), title))
            conn.commit()
            short = f"{request.host_url.rstrip('/')}/{custom_code}"
            resp = {'short_url': short}
            if want_qr:
                resp['qr'] = make_qr_dataurl(short)
            if title:
                resp['title'] = title
            return jsonify(resp)
        except sqlite3.IntegrityError:
            return jsonify({'error': 'custom_code already exists'}), 409

    # insert then determine code according to code_mode
    cur.execute('INSERT INTO urls(original_url, created_at, expire_at, max_clicks, password_hash, one_time, title) VALUES (?,?,?,?,?,?,?)',
                (original, now_ts(), expire_at, max_clicks, pw_hash, int(one_time), title))
    rowid = cur.lastrowid

    if code_mode == 'numeric':
        code = str(rowid)
    elif code_mode == 'hash':
        code = encode_base62(rowid)
    elif code_mode == 'random':
        # ensure uniqueness (retry a few times)
        attempt = 0
        code = make_random_code(random_length)
        while attempt < 6:
            try:
                cur.execute('UPDATE urls SET code=? WHERE id=?', (code, rowid))
                conn.commit()
                break
            except sqlite3.IntegrityError:
                attempt += 1
                code = make_random_code(random_length)
        else:
            conn.rollback()
            return jsonify({'error': 'failed to generate unique random code'}), 500
        # already updated, return
        short = f"{request.host_url.rstrip('/')}/{code}"
        res = {'short_url': short}
        if want_qr:
            res['qr'] = make_qr_dataurl(short)
        if title:
            res['title'] = title
        conn.close()
        return jsonify(res)
    else:
        # default fallback
        code = str(rowid)

    # set code for numeric/hash modes
    try:
        cur.execute('UPDATE urls SET code=? WHERE id=?', (code, rowid))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({'error': 'code collision, try again'}), 500
    conn.close()

    short = f"{request.host_url.rstrip('/')}/{code}"
    res = {'short_url': short}
    if want_qr:
        res['qr'] = make_qr_dataurl(short)
    if title:
        res['title'] = title
    return jsonify(res)


@app.route('/api/stats/<code>', methods=['GET'])
def api_stats(code):
    conn = db_conn()
    cur = conn.cursor()
    cur.execute('SELECT * FROM urls WHERE code=?', (code,))
    row = cur.fetchone()
    if not row:
        return jsonify({'error': 'not found'}), 404
    data = dict(row)
    # convert ints where needed
    return jsonify({
        'code': data['code'],
        'original_url': data['original_url'],
        'created_at': data['created_at'],
        'expire_at': data['expire_at'],
        'max_clicks': data['max_clicks'],
        'clicks': data['clicks'],
        'one_time': bool(data['one_time']),
        'title': data['title']
    })


@app.route('/<code>', methods=['GET'])
def redirect_code(code):
    conn = db_conn()
    cur = conn.cursor()
    now = now_ts()

    # fetch row to check password requirement first
    cur.execute('SELECT password_hash FROM urls WHERE code=?', (code,))
    r = cur.fetchone()
    if not r:
        conn.close()
        abort(404)

    password_hash = r['password_hash']
    if password_hash:
        provided = request.args.get('pw') or request.headers.get('X-LINK-PW')
        if not provided or hash_pw(provided) != password_hash:
            # minimal HTML password form
            html = ("<html><body><h3>Password required</h3>"
                    "<form method='get'>"
                    "<input name='pw' type='password' placeholder='password'/>"
                    "<input type='submit' value='Go'/>"
                    "</form></body></html>")
            conn.close()
            return Response(html, mimetype='text/html')

    # atomic update: increment clicks, and if one_time=1 set expire_at=now.
    # only do the update if the link isn't expired and hasn't hit max_clicks.
    cur.execute("""
        UPDATE urls
        SET clicks = clicks + 1,
            expire_at = CASE WHEN one_time = 1 THEN ? ELSE expire_at END
        WHERE code = ?
          AND (expire_at IS NULL OR expire_at > ?)
          AND (max_clicks IS NULL OR clicks < max_clicks)
    """, (now, code, now))

    if cur.rowcount == 0:
        conn.commit()
        conn.close()
        return jsonify({'error': 'link expired or click limit reached'}), 410

    # success: fetch original URL (row already updated)
    cur.execute('SELECT original_url FROM urls WHERE code = ?', (code,))
    row = cur.fetchone()
    if not row:
        conn.commit()
        conn.close()
        return jsonify({'error': 'not found after update'}), 404

    original = row['original_url']
    conn.commit()
    conn.close()
    return redirect(original, code=302)


# ----------------------------- CLI client -----------------------------

def cli_shorten(args):
    payload = {'url': args.url}
    if args.custom_code:
        payload['custom_code'] = args.custom_code
    if args.expire_seconds:
        payload['expire_seconds'] = args.expire_seconds
    if args.max_clicks:
        payload['max_clicks'] = args.max_clicks
    if args.password:
        payload['password'] = args.password
    if args.one_time:
        payload['one_time'] = True
    if args.qr:
        payload['qr'] = True
    # new: code mode
    payload['code_mode'] = args.mode or 'numeric'
    if args.mode == 'random' and args.random_length:
        payload['random_length'] = args.random_length

    r = requests.post(args.api, json=payload, timeout=10)
    try:
        r.raise_for_status()
        data = r.json()
        print('Short URL:', data.get('short_url'))
        if 'title' in data:
            print('Title:', data.get('title'))
        if 'qr' in data and data['qr']:
            # save QR to file
            b64 = data['qr'].split(',', 1)[1]
            out = args.qr_out or 'qrcode.png'
            with open(out, 'wb') as f:
                f.write(base64.b64decode(b64))
            print('QR saved to', out)
    except Exception as e:
        print('Error:', r.text)


def cli_stats(args):
    url = args.api.rstrip('/') + '/stats/' + args.code
    r = requests.get(url, timeout=10)
    try:
        r.raise_for_status()
        print(json.dumps(r.json(), indent=2))
    except Exception:
        print('Error:', r.text)


def cli_batch(args):
    # CSV input with header 'url'
    import csv
    out_file = args.out or 'shortened.csv'
    rows = []
    with open(args.input, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for rrow in reader:
            url = rrow.get('url')
            if not url: continue
            payload = {'url': url, 'qr': args.qr}
            resp = requests.post(args.api, json=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                rows.append({'url': url, 'short_url': data.get('short_url')})
            else:
                rows.append({'url': url, 'short_url': None, 'error': resp.text})
    # write out
    with open(out_file, 'w', newline='') as csvfile:
        fieldnames = ['url', 'short_url', 'error']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    print('Batch complete ->', out_file)


def cli_help():
    help_text = '''
CLI Link Shortener - Help & Examples

Run server (starts Flask API + redirects):
  python cli_link_shortener.py serve --host 0.0.0.0 --port 8080

Shorten a URL (default MODE = numeric -> produces /1, /2, /3):
  python cli_link_shortener.py shorten --url "https://example.com" --api http://127.0.0.1:8080/api/shorten

Shorten and use obfuscated base62 code (hash mode):
  python cli_link_shortener.py shorten --url "https://example.com" --mode hash --api http://127.0.0.1:8080/api/shorten

Shorten with random code (unpredictable):
  python cli_link_shortener.py shorten --url "https://example.com" --mode random --random-length 8 --api http://127.0.0.1:8080/api/shorten

Create a one-time link (works only on first visit):
  python cli_link_shortener.py shorten --url "https://example.com" --one-time --api http://127.0.0.1:8080/api/shorten

Shorten with expiry and max clicks:
  python cli_link_shortener.py shorten --url "https://example.com" --expire-seconds 3600 --max-clicks 5 --api http://127.0.0.1:8080/api/shorten

Get stats for a code:
  python cli_link_shortener.py stats --code 1 --api http://127.0.0.1:8080/api

Batch shorten CSV (header 'url'):
  python cli_link_shortener.py batch --input urls.csv --api http://127.0.0.1:8080/api/shorten

Notes:
 - Default shorten mode is numeric (incrementing IDs). Use --mode hash or --mode random to make codes harder to guess.
 - For random mode, set --random-length to change generated code length (default 6).
 - Database path can be changed without editing code: set environment variable SHORT_DB=/path/to/shorty.db
 - Password-protected links require ?pw=yourpw on redirect or header X-LINK-PW.
 - QR codes require the 'qrcode' package.
 
 - The server stores data in the SQLite file defined by the SHORT_DB environment variable
#   (default: ./shorty.db). To persist or move the DB without changing code, set SHORT_DB
#   before starting the server, e.g.:
#     SHORT_DB=/home/user/data/shorty.db python cli_link_shortener.py serve
# - The implementation uses an atomic update pattern for one-time links and max-clicks
#   to avoid race conditions. For very high traffic consider migrating to Postgres/MySQL.
# - To reset a link's click counter or change max_clicks manually:
#     sqlite3 shorty.db "UPDATE urls SET clicks=0, max_clicks=10, expire_at=NULL WHERE code='YOURCODE';"
# - Password-protected links require the secret via query (?pw=secret) or header X-LINK-PW.
# - QR code generation is optional (install qrcode[pil]). The API returns a data URL
#   when QR is requested and the library is present.
# - For local testing of custom hostnames, edit /etc/hosts (use only on machines you control).
'''
    print(help_text)


def main():
    parser = argparse.ArgumentParser(prog='cli_link_shortener')
    sub = parser.add_subparsers(dest='cmd')

    # serve
    pserve = sub.add_parser('serve')
    pserve.add_argument('--host', default='127.0.0.1')
    pserve.add_argument('--port', type=int, default=8080)

    # shorten
    pshort = sub.add_parser('shorten')
    pshort.add_argument('--url', required=True)
    pshort.add_argument('--api', default='http://127.0.0.1:8080/api/shorten')
    pshort.add_argument('--custom-code')
    pshort.add_argument('--expire-seconds', type=int)
    pshort.add_argument('--max-clicks', type=int)
    pshort.add_argument('--password')
    pshort.add_argument('--one-time', action='store_true')
    pshort.add_argument('--qr', action='store_true')
    pshort.add_argument('--qr-out')
    pshort.add_argument('--mode', choices=['numeric','hash','random'], default='numeric', help='code generation mode')
    pshort.add_argument('--random-length', type=int, default=6, help='length for random mode')

    # stats
    pstats = sub.add_parser('stats')
    pstats.add_argument('--code', required=True)
    pstats.add_argument('--api', default='http://127.0.0.1:8080/api')

    # batch
    pbatch = sub.add_parser('batch')
    pbatch.add_argument('--input', required=True, help='CSV input file with header url')
    pbatch.add_argument('--api', default='http://127.0.0.1:8080/api/shorten')
    pbatch.add_argument('--out')
    pbatch.add_argument('--qr', action='store_true')

    # help
    phelp = sub.add_parser('help')

    args = parser.parse_args()

    if args.cmd == 'serve':
        init_db()
        print('Starting server on', args.host, args.port)
        app.run(host=args.host, port=args.port, debug=False)
    elif args.cmd == 'shorten':
        cli_shorten(args)
    elif args.cmd == 'stats':
        cli_stats(args)
    elif args.cmd == 'batch':
        cli_batch(args)
    elif args.cmd == 'help' or args.cmd is None:
        cli_help()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
