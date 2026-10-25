"""Cybersecurity Learning Suite: classroom demonstrations, NOT production security infrastructure."""
import base64
import hashlib
import ipaddress
import json
import math
import os
import random
import secrets
import sqlite3
import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).parent
DB_PATH = ROOT / 'suite.sqlite3'
app = Flask(__name__)
CORS(app, resources={r'/api/*': {'origins': ['http://localhost:5173', 'http://127.0.0.1:5173']}})
lock = Lock()
sessions = {}  # ephemeral demo keys; restarting backend clears sessions
handshakes = {}
traffic_history = defaultdict(lambda: deque(maxlen=40))
failed_logins = defaultdict(deque)


def db():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, salt TEXT NOT NULL, public_pem TEXT NOT NULL, cert_pem TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS firewall (id INTEGER PRIMARY KEY, source TEXT NOT NULL DEFAULT '*', destination TEXT NOT NULL DEFAULT '*', port TEXT NOT NULL DEFAULT '*', protocol TEXT NOT NULL DEFAULT '*', action TEXT NOT NULL CHECK(action IN ('ALLOW','BLOCK')));
        CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY, created TEXT NOT NULL, kind TEXT NOT NULL, severity TEXT NOT NULL, detail TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS packets (id INTEGER PRIMARY KEY, created TEXT NOT NULL, source TEXT NOT NULL, destination TEXT NOT NULL, port INTEGER NOT NULL, protocol TEXT NOT NULL, action TEXT NOT NULL);
        ''')
        if not c.execute('SELECT 1 FROM firewall LIMIT 1').fetchone():
            c.executemany('INSERT INTO firewall(source,destination,port,protocol,action) VALUES(?,?,?,?,?)', [('*','*','23','TCP','BLOCK'), ('*','*','22','TCP','ALLOW')])


def body():
    return request.get_json(silent=True) or {}


def fail(msg, code=400):
    return jsonify(error=msg), code


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def pub_pem(key):
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def private_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()


def make_cert(username, key):
    # Intentionally SELF-SIGNED, not a trusted CA-issued certificate.
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])
    dt = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(dt - timedelta(minutes=1)).not_valid_after(dt + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def auth():
    token = request.headers.get('Authorization', '').removeprefix('Bearer ').strip()
    return sessions.get(token)


@app.errorhandler(Exception)
def errors(ex):
    if isinstance(ex, sqlite3.IntegrityError):
        return fail('Username already exists', 409)
    if isinstance(ex, ValueError):
        return fail(str(ex))
    app.logger.exception('Request failed')
    return fail('Request failed. Check inputs and backend logs.', 500)


@app.get('/api/health')
def health():
    return jsonify(status='ok', project='Cybersecurity Learning Suite', student='Ansh Shukla', roll='2420090100', department='CSIT')


@app.post('/api/auth/register')
def register():
    d = body()
    username = str(d.get('username', '')).strip()
    password = str(d.get('password', ''))
    if not (3 <= len(username) <= 40 and username.replace('_', '').isalnum()):
        return fail('Username must be 3–40 alphanumeric/underscore characters')
    if len(password) < 8:
        return fail('Use a password of at least 8 characters')
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 250000).hex()
    cert = make_cert(username, key)
    with db() as c:
        c.execute('INSERT INTO users(username,password_hash,salt,public_pem,cert_pem) VALUES(?,?,?,?,?)', (username, digest, salt, pub_pem(key), cert))
    # Demo-only: private key is returned once and not saved server-side.
    return jsonify(message='Registered. Save your private key locally; it cannot be recovered.', private_key=private_pem(key), public_key=pub_pem(key), certificate=cert), 201


@app.post('/api/auth/login')
def login():
    d = body()
    with db() as c:
        user = c.execute('SELECT * FROM users WHERE username=?', (d.get('username', ''),)).fetchone()
    if not user:
        return fail('Invalid login', 401)
    digest = hashlib.pbkdf2_hmac('sha256', str(d.get('password', '')).encode(), bytes.fromhex(user['salt']), 250000).hex()
    if not secrets.compare_digest(digest, user['password_hash']):
        return fail('Invalid login', 401)
    token = secrets.token_urlsafe(32)
    sessions[token] = user['username']
    return jsonify(token=token, username=user['username'], public_key=user['public_pem'], certificate=user['cert_pem'])


@app.get('/api/keys/directory')
def directory():
    with db() as c:
        entries = c.execute('SELECT username,public_pem FROM users ORDER BY username').fetchall()
    return jsonify(users=[dict(row) for row in entries])


@app.get('/api/keys/certificate/<username>')
def certificate(username):
    with db() as c:
        row = c.execute('SELECT cert_pem FROM users WHERE username=?', (username,)).fetchone()
    if not row:
        return fail('No certificate found', 404)
    return app.response_class(row['cert_pem'], mimetype='application/x-pem-file', headers={'Content-Disposition': f'attachment; filename="{username}.crt"'})


@app.post('/api/rsa')
def rsa_ops():
    d = body()
    op = d.get('operation')
    msg = str(d.get('message', ''))
    try:
        if op in ('encrypt', 'verify'):
            key = serialization.load_pem_public_key(str(d['key']).encode())
            if not isinstance(key, rsa.RSAPublicKey):
                return fail('Expected an RSA public key')
        elif op in ('decrypt', 'sign'):
            key = serialization.load_pem_private_key(str(d['key']).encode(), password=None)
            if not isinstance(key, rsa.RSAPrivateKey):
                return fail('Expected an RSA private key')
        else:
            return fail('Operation must be encrypt, decrypt, sign or verify')
        if op == 'encrypt':
            output = base64.b64encode(key.encrypt(msg.encode(), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))).decode()
        elif op == 'decrypt':
            output = key.decrypt(base64.b64decode(msg, validate=True), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)).decode()
        elif op == 'sign':
            output = base64.b64encode(key.sign(msg.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())).decode()
        else:
            key.verify(base64.b64decode(str(d.get('signature','')), validate=True), msg.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            output = 'Signature is valid.'
        return jsonify(result=output)
    except (KeyError, TypeError, ValueError, UnicodeError, Exception) as ex:
        return fail('Cryptographic operation failed. Check your key, input and signature.')


@app.post('/api/hash')
def hash_text():
    return jsonify(sha512=hashlib.sha512(str(body().get('message', '')).encode()).hexdigest())


# SMALL PARAMETERS ARE FOR EXPLANATION ONLY. Never use for real secrets.
DH_P, DH_G = 7919, 7
@app.get('/api/dh')
def diffie_hellman():
    a, b = secrets.randbelow(DH_P-3)+2, secrets.randbelow(DH_P-3)+2
    A, B = pow(DH_G,a,DH_P), pow(DH_G,b,DH_P)
    return jsonify(p=DH_P,g=DH_G,a=a,b=b,A=A,B=B,alice_secret=pow(B,a,DH_P),bob_secret=pow(A,b,DH_P),note='Tiny classroom parameters; not cryptographically secure.')


# Educational ElGamal signature over tiny prime; intentionally not production cryptography.
EL_P, EL_G = 7919, 7
@app.post('/api/elgamal/sign')
def el_sign():
    message = str(body().get('message', ''))
    x = secrets.randbelow(EL_P-3)+2
    y = pow(EL_G, x, EL_P)
    h = int(hashlib.sha512(message.encode()).hexdigest(), 16) % (EL_P-1)
    k = secrets.randbelow(EL_P-2)+1
    while math.gcd(k, EL_P-1) != 1:
        k = secrets.randbelow(EL_P-2)+1
    r = pow(EL_G,k,EL_P)
    s = ((h-x*r)*pow(k,-1,EL_P-1)) % (EL_P-1)
    return jsonify(hash=hashlib.sha512(message.encode()).hexdigest(), p=EL_P,g=EL_G,public_key=y,private_key=x,r=r,s=s,warning='Small-number illustrative ElGamal only. Not secure for real signatures.')


@app.post('/api/elgamal/verify')
def el_verify():
    d = body()
    try:
        p,g,y,r,s = [int(d[k]) for k in ('p','g','public_key','r','s')]
        if p != EL_P or g != EL_G or not (1 <= r < p and 0 <= s < p-1 and 1 <= y < p):
            return fail('Invalid signature parameters')
        h = int(hashlib.sha512(str(d.get('message','')).encode()).hexdigest(), 16) % (p-1)
        valid = pow(g,h,p) == (pow(y,r,p)*pow(r,s,p))%p
        return jsonify(valid=valid, left=pow(g,h,p), right=(pow(y,r,p)*pow(r,s,p))%p)
    except (KeyError,TypeError,ValueError):
        return fail('Invalid verification input')


TLS_STEPS = [
('Client Hello','Client → Server','Client offers supported TLS versions, cipher suites and an ephemeral key share.'),
('Server Hello','Server → Client','Server chooses TLS 1.3 parameters and responds with its ephemeral key share.'),
('Certificate & Authentication','Server → Client','Server supplies its certificate and proves control of the certificate private key. Real clients validate the chain and hostname.'),
('Shared Traffic Keys','Both','Both derive traffic keys from authenticated (EC)DHE and the handshake transcript using HKDF.'),
('Finished & Encrypted Channel','Both','Finished messages authenticate the transcript. Application data uses authenticated symmetric encryption.')]
SSH_STEPS = [
('Version Exchange','Both','Client and server announce compatible SSH protocol versions.'),
('Algorithm Negotiation','Both','Both negotiate key exchange, host-key, cipher and MAC/AEAD algorithms.'),
('Key Exchange','Both','Ephemeral Diffie-Hellman establishes a shared secret over the untrusted network.'),
('Server Host Authentication','Server → Client','Server signs exchange data with its host private key; client checks a trusted/known host key.'),
('User Authentication','Client → Server','User authenticates using an SSH key or a simulated password.'),
('Encrypted Session','Both','An authenticated and encrypted SSH session is established.')]


@app.post('/api/tunnel/start')
def tunnel_start():
    protocol = str(body().get('protocol','TLS')).upper()
    if protocol not in ('TLS','SSH'):
        return fail('Protocol must be TLS or SSH')
    sid = secrets.token_urlsafe(18)
    with lock:
        handshakes[sid] = {'protocol':protocol,'index':-1}
    return jsonify(session_id=sid, protocol=protocol, total=len(TLS_STEPS if protocol=='TLS' else SSH_STEPS))


@app.post('/api/tunnel/next')
def tunnel_next():
    sid = body().get('session_id')
    with lock:
        state = handshakes.get(sid)
        if not state:
            return fail('No session found; start a new handshake',404)
        steps = TLS_STEPS if state['protocol']=='TLS' else SSH_STEPS
        state['index'] += 1
        idx = state['index']
        if idx >= len(steps):
            return jsonify(done=True,index=len(steps),total=len(steps))
    title, direction, detail = steps[idx]
    return jsonify(done=idx==len(steps)-1, index=idx+1,total=len(steps),title=title,direction=direction,detail=detail,protocol=state['protocol'])


@app.get('/api/ipsec')
def ipsec():
    return jsonify(modes={
        'transport': {'parts':[{'label':'Original IP Header','protected':False},{'label':'ESP Header','protected':False},{'label':'TCP/UDP + Data','protected':True},{'label':'ESP Trailer','protected':True},{'label':'Authentication Tag','protected':False}], 'description':'Transport mode protects the upper-layer payload. The original IP header stays visible; integrity coverage depends on the ESP configuration.'},
        'tunnel': {'parts':[{'label':'New IP Header','protected':False},{'label':'ESP Header','protected':False},{'label':'Original IP Header','protected':True},{'label':'TCP/UDP + Data','protected':True},{'label':'ESP Trailer','protected':True},{'label':'Authentication Tag','protected':False}], 'description':'Tunnel mode wraps and encrypts the original IP packet while a new outer IP header routes it.'}})


def match_ip(rule, incoming):
    if rule == '*': return True
    try: return ipaddress.ip_address(incoming) in ipaddress.ip_network(rule, strict=False)
    except ValueError: return False


def alert(c, kind, severity, detail):
    c.execute('INSERT INTO alerts(created,kind,severity,detail) VALUES(?,?,?,?)',(now(),kind,severity,detail))


@app.route('/api/firewall',methods=['GET','POST'])
def firewall():
    if request.method == 'GET':
        with db() as c: rows = c.execute('SELECT * FROM firewall ORDER BY id DESC').fetchall()
        return jsonify(rules=[dict(r) for r in rows])
    d = body()
    source,destination,port,protocol,action = (str(d.get(k,'*')).strip() for k in ('source','destination','port','protocol','action'))
    protocol,action = protocol.upper(),action.upper()
    for address in (source,destination):
        if address != '*':
            try: ipaddress.ip_network(address,strict=False)
            except ValueError: return fail('Source/destination must be an IP, CIDR, or *')
    if port != '*' and (not port.isdigit() or not 0 <= int(port) <= 65535): return fail('Port must be 0–65535 or *')
    if protocol not in ('*','TCP','UDP','ICMP') or action not in ('ALLOW','BLOCK'): return fail('Invalid protocol/action')
    with db() as c:
        cur = c.execute('INSERT INTO firewall(source,destination,port,protocol,action) VALUES(?,?,?,?,?)',(source,destination,port,protocol,action))
    return jsonify(id=cur.lastrowid),201


@app.route('/api/firewall/<int:rule_id>',methods=['PUT','DELETE'])
def firewall_change(rule_id):
    with db() as c:
        if request.method == 'DELETE':
            c.execute('DELETE FROM firewall WHERE id=?',(rule_id,))
        else:
            d = body()
            row = c.execute('SELECT * FROM firewall WHERE id=?',(rule_id,)).fetchone()
            if not row: return fail('Rule not found',404)
            vals = {k: str(d.get(k,row[k])).strip().upper() if k in ('protocol','action') else str(d.get(k,row[k])).strip() for k in ('source','destination','port','protocol','action')}
            for address in (vals['source'],vals['destination']):
                if address!='*':
                    try: ipaddress.ip_network(address,strict=False)
                    except ValueError: return fail('Invalid address or CIDR')
            if vals['port']!='*' and (not vals['port'].isdigit() or not 0<=int(vals['port'])<=65535): return fail('Invalid port')
            if vals['protocol'] not in ('*','TCP','UDP','ICMP') or vals['action'] not in ('BLOCK','ALLOW'): return fail('Invalid protocol/action')
            c.execute('UPDATE firewall SET source=?,destination=?,port=?,protocol=?,action=? WHERE id=?',(*vals.values(),rule_id))
    return jsonify(ok=True)


@app.post('/api/traffic')
def simulate_traffic():
    d=body()
    source,destination=str(d.get('source','192.168.1.100')),str(d.get('destination','10.0.0.10'))
    try: ipaddress.ip_address(source);ipaddress.ip_address(destination)
    except ValueError: return fail('Enter valid IPv4 or IPv6 addresses')
    try: port=int(d.get('port',80));volume=int(d.get('volume',1))
    except (ValueError,TypeError): return fail('Port and volume must be numbers')
    if not 0<=port<=65535 or not 1<=volume<=500: return fail('Port must be 0–65535, volume 1–500')
    protocol=str(d.get('protocol','TCP')).upper()
    if protocol not in ('TCP','UDP','ICMP'): return fail('Invalid protocol')
    with db() as c:
        rules=c.execute('SELECT * FROM firewall ORDER BY id DESC').fetchall()
        chosen=next((r for r in rules if match_ip(r['source'],source) and match_ip(r['destination'],destination) and (r['port']=='*' or r['port']==str(port)) and r['protocol'] in ('*',protocol)),None)
        action=chosen['action'] if chosen else 'ALLOW'
        c.execute('INSERT INTO packets(created,source,destination,port,protocol,action) VALUES(?,?,?,?,?,?)',(now(),source,destination,port,protocol,action))
        triggered=[]
        if action=='BLOCK': triggered.append(('Firewall','medium',f'{source} → {destination}:{port} blocked by rule #{chosen["id"]}'))
        if port==23: triggered.append(('Rule IDS','high',f'Suspicious Telnet connection from {source}'))
        if d.get('failed_login'):
            attempts=failed_logins[source]
            t=datetime.now(timezone.utc)
            while attempts and (t-attempts[0]).total_seconds()>60: attempts.popleft()
            attempts.append(t)
            if len(attempts)>=5: triggered.append(('Rule IDS','high',f'{len(attempts)} failed SSH logins in 60 seconds from {source}'))
        hist=traffic_history[source]
        if len(hist)>=5:
            mean=statistics.mean(hist)
            sd=statistics.pstdev(hist)
            if volume>mean+3*max(sd,1): triggered.append(('Anomaly IDS','critical',f'Volume {volume} exceeds baseline {mean:.1f} + 3σ ({sd:.1f}) for {source}'))
        hist.append(volume)
        for t,s,msg in triggered: alert(c,t,s,msg)
    return jsonify(action=action,alerts=[{'kind':t,'severity':s,'detail':msg} for t,s,msg in triggered],volume=volume,baseline=list(hist))


@app.get('/api/ids/dashboard')
def dashboard():
    with db() as c:
        alerts=[dict(r) for r in c.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 40')]
        packets=[dict(r) for r in c.execute('SELECT * FROM packets ORDER BY id DESC LIMIT 30')]
    return jsonify(alerts=alerts,packets=packets,baselines={k:list(v) for k,v in traffic_history.items()})


@app.get('/api/threats')
def threats():
    return jsonify(items=[
        {'name':'File Infector Virus','type':'Virus','description':'Attaches malicious code to executable files; often spreads when infected files run.','defense':'Signed software, updated endpoint protection, least privilege, backups.'},
        {'name':'Boot Sector Virus','type':'Virus','description':'Targets boot records and may execute during startup.','defense':'Secure Boot, trusted recovery media, endpoint scanning.'},
        {'name':'Email Worm','type':'Worm','description':'Self-propagating malware distributed via deceptive messages and attachments.','defense':'Attachment filtering, patching, user awareness and restricted macros.'},
        {'name':'Network Worm','type':'Worm','description':'Spreads automatically by exploiting vulnerable services on reachable hosts.','defense':'Patch management, segmentation, egress controls, IDS monitoring.'},
        {'name':'Bastion Host','type':'Firewall Architecture','description':'Hardened gateway for controlled access to sensitive network services.','defense':'MFA, restricted management access, logs, hardened configuration.'}])


if __name__=='__main__':
    init_db()
    app.run(host='127.0.0.1',port=5000,debug=False)
else:
    init_db()
