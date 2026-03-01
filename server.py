"""
CloudSecure - Python Server v2
Haqiqiy AES-256-GCM shifrlash + SQLite baza
Ishga tushirish: python server.py
Keyin: http://localhost:5000
"""

from flask import Flask, send_file, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os, base64, sqlite3, json, secrets
from datetime import datetime

app = Flask(__name__)
CORS(app)

# ── Sozlamalar ─────────────────────────────────────────────────
DB_FILE    = 'cloudsecure.db'
MASTER_KEY = os.environ.get('CLOUDSECURE_KEY', secrets.token_hex(32))


# ════════════════════════════════════════════════════════════════
#   BAZA — SQLite
# ════════════════════════════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS records (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id   TEXT UNIQUE NOT NULL,
            data_type   TEXT,
            owner_id    TEXT,
            algorithm   TEXT DEFAULT 'AES-256-GCM',
            storage     TEXT,
            ciphertext  TEXT NOT NULL,
            nonce       TEXT NOT NULL,
            salt        TEXT NOT NULL,
            size_bytes  INTEGER,
            created_at  TEXT,
            created_time TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            action     TEXT,
            record_id  TEXT,
            detail     TEXT,
            level      TEXT DEFAULT 'info',
            created_at TEXT
        );
    """)
    conn.commit()
    conn.close()


# ════════════════════════════════════════════════════════════════
#   AES-256-GCM SHIFRLASH
# ════════════════════════════════════════════════════════════════
def encrypt(plaintext: str) -> dict:
    """Haqiqiy AES-256-GCM shifrlash"""
    salt  = os.urandom(16)
    nonce = os.urandom(12)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, salt=salt,
        iterations=100_000
    )
    key = kdf.derive(bytes.fromhex(MASTER_KEY))
    ct  = AESGCM(key).encrypt(nonce, plaintext.encode('utf-8'), None)
    return {
        'ciphertext': base64.b64encode(ct).decode(),
        'nonce':      base64.b64encode(nonce).decode(),
        'salt':       base64.b64encode(salt).decode(),
    }

def decrypt(ciphertext: str, nonce: str, salt: str) -> str:
    """AES-256-GCM bilan shifr ochish"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.b64decode(salt),
        iterations=100_000
    )
    key = kdf.derive(bytes.fromhex(MASTER_KEY))
    pt  = AESGCM(key).decrypt(
        base64.b64decode(nonce),
        base64.b64decode(ciphertext),
        None
    )
    return pt.decode('utf-8')


# ── Audit log ──────────────────────────────────────────────────
def log(action, record_id, detail, level='info'):
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_logs(action,record_id,detail,level,created_at) VALUES(?,?,?,?,?)",
        (action, record_id, detail, level, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()


# ════════════════════════════════════════════════════════════════
#   API ENDPOINTLAR
# ════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return send_file('cloud-privacy-db.html')


@app.route('/api/status')
def status():
    conn  = get_db()
    total = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    conn.close()
    return jsonify({
        'status':    '✅ Server ishlayapti',
        'baza':      DB_FILE,
        'shifrlash': 'AES-256-GCM',
        'jami':      total,
        'vaqt':      datetime.now().strftime('%H:%M:%S')
    })


# ── SHIFRLASH + BAZAGA SAQLASH ─────────────────────────────────
@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    """
    Qabul qiladi:  { data, data_type, owner_id, storage }
    Shifrlaydi:    AES-256-GCM
    Saqlaydi:      cloudsecure.db — records jadvalida

    Bazada saqlanadigan ustunlar:
      record_id  — unikal ID (REC-XXXXXX)
      ciphertext — AES-256 shifrlangan matn (base64)
      nonce      — GCM nonce (base64)
      salt       — PBKDF2 salt (base64)
      data_type  — ma'lumot turi
      owner_id   — egasi
      size_bytes — hajmi
      created_at — vaqt
    """
    body      = request.json or {}
    plaintext = body.get('data', '').strip()
    data_type = body.get('data_type', 'Noma\'lum')
    owner_id  = body.get('owner_id', 'USR-ANON')
    storage   = body.get('storage', 'UZ-DC-01')

    if not plaintext:
        return jsonify({'error': 'Ma\'lumot bo\'sh!'}), 400

    # 1. Haqiqiy AES-256-GCM shifrlash
    enc = encrypt(plaintext)

    # 2. Yozuv ID va vaqt
    record_id = 'REC-' + secrets.token_hex(3).upper()
    now       = datetime.now()

    # 3. SQLite bazaga yozish
    conn = get_db()
    conn.execute("""
        INSERT INTO records
          (record_id, data_type, owner_id, algorithm, storage,
           ciphertext, nonce, salt, size_bytes, created_at, created_time)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (
        record_id, data_type, owner_id, 'AES-256-GCM', storage,
        enc['ciphertext'], enc['nonce'], enc['salt'],
        len(plaintext.encode()),
        now.isoformat(),
        now.strftime('%H:%M:%S')
    ))
    conn.commit()
    conn.close()

    log('ENCRYPT', record_id, f'{data_type} | {owner_id}')

    return jsonify({
        'success':       True,
        'record_id':     record_id,
        'algorithm':     'AES-256-GCM',
        'size':          f"{len(plaintext.encode())} bytes",
        'cipher_preview': enc['ciphertext'][:48] + '...',
        'baza_fayl':     DB_FILE,
        'message':       f'{record_id} bazaga muvaffaqiyatli saqlandi!'
    })


# ── SHIFR OCHISH ───────────────────────────────────────────────
@app.route('/api/decrypt/<record_id>')
def api_decrypt(record_id):
    """Bazadan yozuvni topib, AES-256-GCM bilan ochish"""
    conn = get_db()
    row  = conn.execute(
        "SELECT * FROM records WHERE record_id=?", (record_id,)
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({'error': f'{record_id} bazada topilmadi'}), 404

    try:
        plaintext = decrypt(row['ciphertext'], row['nonce'], row['salt'])
        log('DECRYPT', record_id, 'muvaffaqiyatli')
    except Exception as e:
        return jsonify({'error': f'Shifr ochishda xatolik: {str(e)}'}), 500

    return jsonify({
        'success':    True,
        'record_id':  record_id,
        'plaintext':  plaintext,
        'data_type':  row['data_type'],
        'owner_id':   row['owner_id'],
        'algorithm':  row['algorithm'],
        'created_at': row['created_at'],
    })


# ── RO'YXAT ────────────────────────────────────────────────────
@app.route('/api/records')
def api_records():
    """Bazadagi barcha yozuvlar (plaintext ko'rsatilmaydi)"""
    conn    = get_db()
    rows    = conn.execute(
        "SELECT record_id,data_type,owner_id,algorithm,storage,size_bytes,created_time FROM records ORDER BY id DESC"
    ).fetchall()
    conn.close()

    records = [dict(r) for r in rows]
    return jsonify({'total': len(records), 'records': records})


# ── O'CHIRISH ──────────────────────────────────────────────────
@app.route('/api/records/<record_id>', methods=['DELETE'])
def api_delete(record_id):
    conn = get_db()
    cur  = conn.execute("DELETE FROM records WHERE record_id=?", (record_id,))
    conn.commit()
    conn.close()

    if cur.rowcount == 0:
        return jsonify({'error': 'Topilmadi'}), 404

    log('DELETE', record_id, 'o\'chirildi', 'warn')
    return jsonify({'success': True, 'message': f'{record_id} o\'chirildi'})


# ── AUDIT LOG ──────────────────────────────────────────────────
@app.route('/api/audit')
def api_audit():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM audit_logs ORDER BY id DESC LIMIT 50"
    ).fetchall()
    conn.close()
    return jsonify({'logs': [dict(r) for r in rows]})


# ── STATISTIKA ─────────────────────────────────────────────────
@app.route('/api/stats')
def api_stats():
    conn  = get_db()
    total = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    types = conn.execute(
        "SELECT data_type, COUNT(*) as cnt FROM records GROUP BY data_type"
    ).fetchall()
    conn.close()
    return jsonify({
        'total': total,
        'by_type': [dict(r) for r in types]
    })


# ════════════════════════════════════════════════════════════════
#   ISHGA TUSHIRISH
# ════════════════════════════════════════════════════════════════
if __name__ == '__main__':
    init_db()
    print('=' * 50)
    print('  🔐 CloudSecure Server v2')
    print('=' * 50)
    print(f'  💾 Baza:      {DB_FILE}')
    print(f'  🔑 Shifrlash: AES-256-GCM')
    print(f'  🔑 Kalit:     {"env" if os.environ.get("CLOUDSECURE_KEY") else "demo (random)"}')
    print(f'  👉 Brauzer:   http://localhost:5000')
    print('=' * 50)
    print('  To\'xtatish: Ctrl + C')
    print('=' * 50)
    app.run(debug=False, port=5000)
