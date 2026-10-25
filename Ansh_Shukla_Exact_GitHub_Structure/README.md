# CyberAtlas: Cybersecurity Learning Suite

**Author:** Ansh Shukla  
**Roll Number:** 2420090100  
**Department:** CSIT  
**Academic project:** Information Assurance and Security

A single, custom-designed React + Flask + SQLite project containing **all three requested projects**: CryptoVault, SecureTunnel and Sentinel. Its original teal/navy “CyberAtlas” dashboard differentiates the project from other student submissions.

## GitHub repository folder layout (matches the reference screenshot)

```text
Ansh-Shukla-IAAS-Project/
├── Sentinel-backend-new/
│   ├── .gitignore
│   ├── app.py
│   └── requirements.txt
├── Sentinel-frontend-new/
│   ├── src/
│   │   ├── main.jsx
│   │   └── style.css
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
├── backend/
│   ├── app.py
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── main.jsx
│   │   └── style.css
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
├── .gitignore
└── README.md
```

**IMPORTANT:** The `backend` and `frontend` folders are the primary application.
The `Sentinel-backend-new` and `Sentinel-frontend-new` folders are self-contained
alternative copies of the suite, included to mirror the four-folder structure
shown in the reference GitHub screenshot. Both pairs contain all three modules
(CryptoVault, SecureTunnel and Sentinel), not separate running services.
Run only one backend/frontend pair at a time to avoid port conflicts.

To have these **four folders appear directly in GitHub's left-hand file tree**,
upload the **contents of this ZIP** to the repository root (do not upload the ZIP
file itself and do not wrap them in an extra parent folder).

## Modules and features

### 1. CryptoVault
- User registration/login: passwords salted and derived using PBKDF2; public keys stored in SQLite.
- RSA 2048-bit key pair created on registration. Private key displayed once, never saved by the server. **Copy it** before refreshing; its loss is permanent.
- Public key directory and downloadable *self-signed* X.509 certificates, 30-day validity.
- RSA-OAEP(SHA-256) encrypt/decrypt and RSA-PSS(SHA-256) sign/verify with pasted PEM keys.
- SHA-512 digest display.
- Diffie-Hellman step-by-step visualization.
- Classical ElGamal signatures with sign/verify, intentionally small 7919-bit? **No: 7919 is a small integer prime (~13 bits)** for arithmetic demonstrations, not real-world security.

### 2. SecureTunnel
- Server-side stateful TLS **1.3** handshake educational timeline (ClientHello, ServerHello, certificate authentication, ephemeral key agreement, Finished).
- Simplified SSH connection sequence with version exchange, key exchange, host authentication and user authentication.
- Interactive ESP packet diagrams for IPsec transport/tunnel modes, highlighting which packet fields are encrypted.
- **Note:** TLS 1.3 deliberately does not illustrate legacy RSA-encrypted premaster-secret key transport. That approach belongs to older TLS handshakes; modern TLS 1.3 uses (EC)DHE. The steps are explanatory and do not create an actual secure network connection.

### 3. Sentinel
- SQLite-backed firewall rule manager: add, edit, delete; source/destination IP or CIDR, protocol, port, ALLOW/BLOCK.
- Simulated traffic with decision engine (newest matching rule first, default ALLOW).
- Rule-based IDS: Telnet port 23 and five failed SSH logins within a rolling 60-second window.
- Statistical anomaly IDS: sample-volume monitoring with deviation above mean + 3 × max(std dev, 1), after at least five samples.
- Visual dashboard including time-series chart, metrics, alert feed and bastion host concept diagram.
- Static threat encyclopedia: file infector virus, boot sector virus, email worm, network worm, bastion host.

## Requirements
- Python 3.10+ and pip
- Node.js 18+ and npm

## Run locally

**Terminal 1 (backend)**

```bash
cd backend
python -m pip install -r requirements.txt
python app.py
```

Backend runs at http://127.0.0.1:5000. SQLite database is created automatically.

**Terminal 2 (frontend)**

```bash
cd frontend
npm install
npm run dev
```

Open http://127.0.0.1:5173 in Chrome. Keep **both** terminals running.

The React app uses the Vite development proxy to send `/api` requests to Flask. No cloud API keys are necessary.

## Demo walkthrough
1. CryptoVault: register a demo account using a non-personal password, **copy private PEM**, use public PEM to encrypt a short message, paste private PEM and ciphertext to decrypt. Use private PEM to sign and public PEM to verify.
2. Try DH: choose **New exchange** and advance four steps. Both sides compute the same shared secret.
3. SHA-512 and ElGamal: sign the message, then verify. Modify the message and verify again to get an invalid result.
4. SecureTunnel: run TLS and SSH timelines. Toggle IPsec modes.
5. Sentinel: add a blocking rule for TCP port 443, simulate a port-443 packet, then try suspicious traffic on port 23. Repeat failed logins five times and watch IDS alerts.
6. For anomaly detection, generate at least five low-volume packets from a source then send a higher-volume sample from that IP.

## API quick reference

| Route | Method | Purpose |
|---|---|---|
| `/api/health` | GET | Status/student details |
| `/api/auth/register` | POST | Register and generate RSA key |
| `/api/auth/login` | POST | Authenticate |
| `/api/keys/directory` | GET | Public key directory |
| `/api/keys/certificate/<username>` | GET | Download X.509 certificate |
| `/api/rsa` | POST | Encrypt/decrypt/sign/verify |
| `/api/hash` | POST | SHA-512 |
| `/api/dh` | GET | DH example |
| `/api/elgamal/sign` | POST | ElGamal signature |
| `/api/elgamal/verify` | POST | Verify signature |
| `/api/tunnel/start` | POST | Start TLS/SSH demonstration |
| `/api/tunnel/next` | POST | Step forward |
| `/api/ipsec` | GET | Packet structure definitions |
| `/api/firewall` | GET/POST | View/add rules |
| `/api/firewall/<id>` | PUT/DELETE | Edit/delete rules |
| `/api/traffic` | POST | Simulate traffic and IDS |
| `/api/ids/dashboard` | GET | Recent packets, alerts, baselines |
| `/api/threats` | GET | Threat encyclopedia |

## Important limitations
This is an **academic simulator**. No real packets are captured, filtered or transmitted. The firewall does not change OS firewall settings. TLS/SSH visualizers represent protocol sequencing, not real TLS or SSH transports. DH and ElGamal intentionally use small illustrative parameters, **never use for real cryptographic protection**. Self-signed X.509 certificates are not browser-trusted; this project does not implement a real CA or a fully authenticated PKI. Password login is demonstrational and lacks production rate limiting, persistence for sessions, CSRF protection, and other production hardening. Never enter real credentials or sensitive data.

## Upload to GitHub
Create a repository, then upload **the contents** of the extracted project folder, keeping the `backend/`, `frontend/` and `README.md` structure. Do not upload `node_modules`, `.venv`, `suite.sqlite3`, or any real private keys.

## Folder structure
```
CyberAtlas/
├── backend/
│   ├── app.py
│   └── requirements.txt
├── frontend/
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   └── src/
│       ├── main.jsx
│       └── style.css
├── .gitignore
└── README.md
```
