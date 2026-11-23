# Certificate Transparency (CT) & Rogue-CA Detection System

This project implements a **Toy PKI** and a **Certificate Transparency (CT) Monitoring & Revocation System** in Python to demonstrate how rogue or unauthorized certificates issued by a compromised Root CA can be detected and mitigated.

---

## 📁 Project Architecture

```
toy_pki_ct/
├── ca/
│   ├── __init__.py
│   └── root_ca.py          # Root CA: Key management, self-signed root cert, leaf issuance, X.509 CRL
├── storage/
│   ├── __init__.py
│   └── database.py         # SQLite manager (authorized domains, certificates, CT log, revocations, alerts)
├── ct/
│   ├── __init__.py
│   ├── merkle_tree.py      # RFC 6962 SHA-256 Merkle tree (audit & consistency proofs)
│   └── log_server.py       # CT Log Server: SCT issuance, Signed Tree Head (STH), persistence
├── monitor/
│   ├── __init__.py
│   └── auditor.py          # CT Monitor: audits CT log, checks auth registry, auto-revokes rogue certs
├── client/
│   ├── __init__.py
│   └── verifier.py         # Traditional (vulnerable) vs CT-Aware (protected) TLS clients
├── certs/                  # Persisted keys, certificates, and CRLs
│   ├── ca.key
│   ├── ca.crt
│   ├── ca.crl
│   ├── ct_log.key          # Independent CT Log signing key
│   ├── ct_log.pub
│   ├── owners/             # Legitimate owner private keys
│   └── attacker/           # Attacker rogue keys
├── data/
│   └── pki_ct.db           # SQLite database
├── cli.py                  # CLI tool for TA live demo & PKI management
├── demo_defense.py         # Automated live defense script for TA grading
├── test_ca.py              # Test suite for CA lifecycle & CRL
├── test_ct.py              # Test suite for Merkle tree & CT log
├── test_monitor.py         # Test suite for Monitor & Client verification
└── README.md
```

---

##  Live Defense Demonstration


You can run the full automated defense demonstration with a single command passing the nominated domain:

```bash
# Example: TA nominates "bank.corp" owned by "Bank Admin"
python demo_defense.py --domain bank.corp --owner "Bank Admin"
```

This single command executes 7 stages:
1. Registers the target domain and its legitimate owner public key in the Authorization Lookup Table.
2. Issues a legitimate X.509 certificate and logs it to the CT Merkle tree.
3. Simulates the compromised CA: Deliberately issues a rogue certificate for the target domain using an attacker's key.
4. **Traditional Client Evaluation**: Shows the traditional TLS client blindly accepting the rogue certificate (vulnerable to MITM).
5. **CT Monitor Execution**: Audits the CT log, verifies the Merkle inclusion proof against the Signed Tree Head, flags the public key mismatch, and auto-revokes the rogue cert.
6. **CT-Aware Client Evaluation**: Shows the CT-aware client detecting the revocation and terminating the connection.
7. **Append-Only Consistency Proof**: Verifies that no past log entries were altered or removed.

---

##  Individual CLI Commands

### 1. Initialize the Root CA
```bash
python cli.py init-ca
```

### 2. Register Authorized Domain Owner
```bash
python cli.py register-domain --domain alice.domain --owner "Alice Smith"
```

### 3. Issue Legitimate Certificate
```bash
python cli.py issue --domain alice.domain
```

### 4. Issue Rogue Certificate (Simulating Compromised CA)
```bash
python cli.py issue-rogue --domain alice.domain
```

### 5. Inspect CT Log & Signed Tree Head (STH)
```bash
python cli.py ct-status
```

### 6. Verify Merkle Inclusion Proof (Audit Proof)
```bash
python cli.py ct-audit --serial <SERIAL>
```

### 7. Run CT Monitor Audit
```bash
python cli.py monitor
```

### 8. Compare Traditional vs CT-Aware Client
```bash
python cli.py verify-client --serial <SERIAL>
```

### 9. View Recorded Monitor Security Alerts
```bash
python cli.py list-alerts
```

### 10. Run All Test Suites
```bash
python test_ca.py
python test_ct.py
python test_monitor.py
```

---

##  Security Threat Model & Mechanism Breakdown

1. **Threat Model**:
   - The Root CA is compromised or has a rogue insider.
   - The attacker can issue validly-signed X.509 certificates for any domain (e.g. `alice.domain`) using the attacker's public key.
   - The attacker **cannot** tamper with the domain authorization database (auth registry) or the append-only CT log.

2. **Defense Mechanism**:
   - **CT Log (RFC 6962-style Merkle Tree)**: Every issued certificate is appended to the Merkle tree log. The Merkle root summarizes the history, and audit/inclusion proofs verify tamper-resistance.
   - **Monitor Process**: Continuously audits log entries. For every certificate issued for `alice.domain`, the monitor compares the certificate's public key against the authorized public key in the registry. Discrepancies immediately trigger a Rogue Certificate alert.
   - **Revocation**: The rogue certificate serial number is transferred to the revocation list and added to a signed X.509 CRL. Clients check the CRL or monitor before trusting the certificate.
