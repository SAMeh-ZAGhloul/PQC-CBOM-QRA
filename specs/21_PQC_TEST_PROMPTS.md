# 22 -- Sample PQC Test Prompts

> **For:** Validating scanner workers, SLM fallback, CBOM classifier, and end-to-end detection
> **Version:** 1.0 | **Date:** June 2025

---

## Purpose

This document provides sample PQC (Post-Quantum Cryptography) test prompts for every detection layer in the platform:

1. **AST scanner** -- source code samples for tree-sitter + regex detection
2. **Binary scanner** -- ELF/PE symbol target patterns
3. **Certificate scanner** -- PQC cert test vectors
4. **SLM/llama.cpp prompts** -- raw prompt + expected JSON for crypto classification
5. **Zeek network patterns** -- TLS 1.3 + PQC hybrid cipher suites
6. **CBOM classifier inputs** -- algorithm name → expected QuantumClass
7. **QARS/QSRI test vectors** -- complete scan result expectations
8. **Traffic sim PQC scenario** -- test data for the `pqc_demo.py` scenario

---

## 1. AST Scanner -- PQC Source Code Samples

### 1.1 Python -- ML-KEM via `pyoqs` / `liboqs-python`

**File:** `samples/pqc/pqc_key_encaps.py`
```python
"""Sample: PQC key encapsulation using ML-KEM (FIPS 203)."""
import oqs

def generate_kem_keys():
    """Generate ML-KEM-768 keypair for testing."""
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    public_key = kem.generate_keypair()
    secret_key = kem.export_secret_key()
    return public_key, secret_key

def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Encapsulate a shared secret using ML-KEM-768."""
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret

def decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate the shared secret using ML-KEM-768."""
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    kem.import_secret_key(secret_key)
    return kem.decap_secret(ciphertext)

# Expected scanner findings:
#   algorithm=ML-KEM-768, crypto_type=pqc_kem, quantum_class=pqc
#   (from string literal "ML-KEM-768" + oqs import)
```

**Expected scanner output:**
```json
[
  {
    "algorithm": "ML-KEM-768",
    "key_size": null,
    "crypto_type": "pqc_kem",
    "confidence": "high",
    "line_number": 8,
    "raw_evidence": "ML-KEM-768"
  }
]
```

### 1.2 Python -- ML-DSA via `pyoqs`

**File:** `samples/pqc/pqc_signatures.py`
```python
"""Sample: PQC digital signatures using ML-DSA (FIPS 204)."""
import oqs

def sign_message(message: bytes, private_key: bytes) -> bytes:
    """Sign a message using ML-DSA-65."""
    sig = oqs.Signature("ML-DSA-65")
    signature = sig.sign(message, private_key)
    return signature

def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an ML-DSA-65 signature."""
    verifier = oqs.Signature("ML-DSA-65")
    return verifier.verify(message, signature, public_key)

def slh_dsa_sign(message: bytes, private_key: bytes) -> bytes:
    """Sign using SLH-DSA (FIPS 205) - stateless hash-based."""
    sig = oqs.Signature("SLH-DSA-SHAKE-128s")
    return sig.sign(message, private_key)

# Expected scanner findings:
#   algorithm=ML-DSA-65, crypto_type=pqc_signature
#   algorithm=SLH-DSA, crypto_type=pqc_signature
```

### 1.3 Python -- Hybrid ECDHE + ML-KEM (OpenQuantumSafe)

**File:** `samples/pqc/hybrid_kex.py`
```python
"""Sample: Hybrid key exchange combining ECDHE + ML-KEM."""
import oqs
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def hybrid_kem_exchange():
    """
    Perform hybrid key exchange:
    Classical: ECDHE (X25519)
    PQC:       ML-KEM-768
    Combined:  SHA-385(ecdh_secret || kem_secret)
    """
    # PQC part
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pq_public = kem.generate_keypair()

    # Classical part
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Hybrid - both keys serialized in TLS handshake
    return pq_public, public_key

# Expected scanner findings:
#   algorithm=ML-KEM-768, crypto_type=pqc_kem
#   algorithm=ECDSA, crypto_type=digital_signature  (from ec.SECP256R1)
#   algorithm=X25519, crypto_type=key_exchange? No, curve P-256 here
```

### 1.4 Python -- FALCON Signature (Non-NIST Standardized)

**File:** `samples/pqc/falcon_sign.py`
```python
"""Sample: FALCON lattice-based signature (not yet FIPS standardized)."""
import oqs

def falcon_demo():
    """Demonstrate FALCON-512 signatures."""
    signer = oqs.Signature("FALCON-512")
    public_key = signer.generate_keypair()
    message = b"Critical transaction - PQC signed"
    signature = signer.sign(message)
    is_valid = signer.verify(message, signature, public_key)
    return is_valid

# Expected scanner findings:
#   algorithm=FALCON, crypto_type=pqc_signature
#   Normalized: FALCON -> QuantumClass.PQC
```

### 1.5 Python -- Kyber (Pre-Standard Name Detection)

**File:** `samples/pqc/kyber_legacy.py`
```python
"""Sample: Using pre-standard Kyber name (should map to ML-KEM)."""
import oqs

def legacy_kyber():
    """Use Kyber-768 (pre-standardization name for ML-KEM-768)."""
    kem = oqs.KeyEncapsulation("Kyber-768")
    pk = kem.generate_keypair()
    ct, ss = kem.encap_secret(pk)
    return ct, ss

# Expected scanner findings:
#   algorithm=Kyber-768 -> normalized to ML-KEM-768
#   quantum_class=pqc, nist_fips=FIPS 203
#   (classifier maps KYBER -> ML-KEM)
```

### 1.6 Python -- Dilithium (Pre-Standard Name Detection)

**File:** `samples/pqc/dilithium_legacy.py`
```python
"""Sample: Using pre-standard Dilithium name (should map to ML-DSA)."""
import oqs

def legacy_dilithium():
    """Use Dilithium-3 (pre-standardization name for ML-DSA-65)."""
    sig = oqs.Signature("Dilithium-3")
    pk = sig.generate_keypair()
    sig_bytes = sig.sign(b"test message")
    return pk, sig_bytes

# Expected scanner findings:
#   algorithm=Dilithium-3 -> normalized to ML-DSA-65
#   quantum_class=pqc, nist_fips=FIPS 204
```

### 1.7 Python -- Classical Vulnerable (for contrast testing)

**File:** `samples/pqc/classical_vulnerable.py`
```python
"""Sample: Classical algorithms for contrast - should flag as vulnerable."""
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, dh
from cryptography.hazmat.primitives import hashes

# RSA - quantum vulnerable
private_key = rsa.generate_private_key(65537, 2048)

# ECDSA - quantum vulnerable
ec_key = ec.generate_private_key(ec.SECP256R1())

# DSA - quantum vulnerable
dsa_params = dsa.generate_parameters(2048)
dsa_key = dsa_params.generate_private_key()

# DH - quantum vulnerable
dh_params = dh.generate_parameters(generator=2, key_size=2048)
dh_private = dh_params.generate_private_key()

# MD5 - deprecated, partially_safe
md5_hash = hashes.Hash(hashes.MD5())

# Expected scanner findings:
#   RSA-2048,    vulnerable, asymmetric_encryption
#   ECDSA,       vulnerable, digital_signature
#   DSA,         vulnerable, digital_signature
#   DH,          vulnerable, key_exchange
#   MD5,         partially_safe, hash
```

### 1.8 Go -- PQC with `cloudflare/circl`

**File:** `samples/pqc/go_pqc.go`
```go
package main

import (
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/sha256"
    "fmt"

    "github.com/cloudflare/circl/kem/kyber/kyber768"
    "github.com/cloudflare/circl/sign/dilithium/mode3"
)

func main() {
    // Classical (vulnerable)
    rsaKey, _ := rsa.GenerateKey(nil, 2048)
    ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), nil)
    _ = sha256.Sum256([]byte("test"))

    // PQC (safe)
    pqPub, pqPriv, _ := kyber768.GenerateKey(nil)
    dilPub, dilPriv, _ := mode3.GenerateKey(nil)

    fmt.Println("Hybrid keys ready", rsaKey, ecKey, pqPub, pqPriv, dilPub, dilPriv)
}

// Expected scanner findings:
//   algorithm=RSA,        quantum_class=vulnerable
//   algorithm=ECDSA,      quantum_class=vulnerable
//   algorithm=SHA-256,    quantum_class=partially_safe
//   algorithm=ML-KEM-768, quantum_class=pqc         (kyber768 -> ML-KEM-768)
//   algorithm=ML-DSA-65,  quantum_class=pqc         (mode3 -> ML-DSA-65)
```

### 1.9 Java -- PQC Bouncy Castle PQC

**File:** `samples/pqc/JavaPQC.java`
```java
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import javax.crypto.Cipher;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.MLDSAParameterSpec;

public class JavaPQC {
    public static void main(String[] args) throws Exception {
        java.security.Security.addProvider(new BouncyCastlePQCProvider());

        // ML-KEM key generation (FIPS 203)
        KeyPairGenerator kemGen = KeyPairGenerator.getInstance("ML-KEM");
        kemGen.initialize(new MLKEMParameterSpec(768));  // ML-KEM-768
        KeyPair kemKeyPair = kemGen.generateKeyPair();

        // ML-DSA signing (FIPS 204)
        KeyPairGenerator dsaGen = KeyPairGenerator.getInstance("ML-DSA");
        dsaGen.initialize(new MLDSAParameterSpec(65));   // ML-DSA-65
        KeyPair dsaKeyPair = dsaGen.generateKeyPair();

        Signature signer = Signature.getInstance("ML-DSA");
        signer.initSign(dsaKeyPair.getPrivate());
        signer.update("message".getBytes());
        byte[] signature = signer.sign();

        // Classical (vulnerable) for contrast
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        KeyPair rsaKeyPair = rsaGen.generateKeyPair();

        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");

        java.security.MessageDigest md5 = java.security.MessageDigest.getInstance("MD5");
    }
}

// Expected scanner findings:
//   algorithm=ML-KEM-768, quantum_class=pqc
//   algorithm=ML-DSA-65,  quantum_class=pqc
//   algorithm=RSA,        quantum_class=vulnerable
//   algorithm=AES-256?    quantum_class=safe (AES/GCM)
//   algorithm=MD5,        quantum_class=partially_safe
```

### 1.10 JavaScript/TypeScript -- PQC via `pqcrypto` npm

**File:** `samples/pqc/ts_pqc.ts`
```typescript
import { kem } from 'pqcrypto/mlkem768';
import { sign } from 'pqcrypto/mldsa65';
import * as crypto from 'node:crypto';

async function pqcDemo() {
  // ML-KEM-768 key encapsulation
  const { publicKey, secretKey } = await kem.keypair();
  const { ciphertext, sharedSecret } = await kem.encapsulate(publicKey);
  const decrypted = await kem.decapsulate(ciphertext, secretKey);

  // ML-DSA-65 digital signature
  const { publicKey: pk, secretKey: sk } = await sign.keypair();
  const message = Buffer.from('PQC test message');
  const signature = await sign.sign(message, sk);
  const isValid = await sign.verify(message, signature, pk);

  // Classical (for contrast)
  const rsaKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const md5Hash = crypto.createHash('md5').update('data').digest('hex');
}

// Expected scanner findings:
//   algorithm=ML-KEM-768, quantum_class=pqc
//   algorithm=ML-DSA-65,  quantum_class=pqc
//   algorithm=RSA,        quantum_class=vulnerable
//   algorithm=MD5,        quantum_class=partially_safe
```

---

## 2. SLM/llama.cpp -- Crypto Detection Prompt Patterns

### 2.1 PQC Code with Valid JSON Return

**Input prompt:**
```
You are a cryptographic security analyst.
Analyze the code or configuration below for cryptographic operations.

Rules:
- Look for: algorithm names, key sizes, hash functions, cipher modes, crypto API calls
- Include: hardcoded values, config strings, import statements, function calls
- Skip: comments that only mention crypto without using it

Return JSON ONLY -- no markdown, no explanation, no backticks:
{
  "findings": [
    {
      "algorithm": "exact algorithm name (e.g. RSA, AES-256, SHA-1, ECDSA)",
      "quantum_vulnerable": true or false,
      "confidence": "high or medium or low",
      "reason": "one sentence explaining where and why",
      "line_number": integer or null
    }
  ]
}

If no cryptographic operations found, return: {"findings": []}

Code to analyze:
<code>
import oqs

kem = oqs.KeyEncapsulation("ML-KEM-768")
public_key = kem.generate_keypair()
ciphertext, shared_secret = kem.encap_secret(public_key)
</code>
```

**Expected JSON response:**
```json
{
  "findings": [
    {
      "algorithm": "ML-KEM-768",
      "quantum_vulnerable": false,
      "confidence": "high",
      "reason": "PQC KEM using ML-KEM-768 (FIPS 203) for key encapsulation",
      "line_number": 3
    }
  ]
}
```

### 2.2 Mixed Classical + PQC Code

**Input prompt (content truncated to 2000 chars):**
```
<code>
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes, serialization
import oqs

# Classical - vulnerable
rsa_key = rsa.generate_private_key(65537, 2048)
ec_key = ec.generate_private_key(ec.SECP256R1())
sha1_hash = hashes.Hash(hashes.SHA1())

# PQC - quantum-safe
kem = oqs.KeyEncapsulation("ML-KEM-768")
pk = kem.generate_keypair()
ct, ss = kem.encap_secret(pk)

sig = oqs.Signature("ML-DSA-65")
signature = sig.sign(b"test", sk)
</code>
```

**Expected JSON response:**
```json
{
  "findings": [
    {
      "algorithm": "RSA",
      "quantum_vulnerable": true,
      "confidence": "high",
      "reason": "RSA-2048 generated for asymmetric encryption; broken by Shor's algorithm",
      "line_number": 6
    },
    {
      "algorithm": "ECDSA",
      "quantum_vulnerable": true,
      "confidence": "high",
      "reason": "ECDSA with P-256; elliptic curve discrete log solved by Shor's",
      "line_number": 7
    },
    {
      "algorithm": "SHA-1",
      "quantum_vulnerable": false,
      "confidence": "high",
      "reason": "SHA-1 used for hashing; deprecated by NIST, collision attacks demonstrated",
      "line_number": 8
    },
    {
      "algorithm": "ML-KEM-768",
      "quantum_vulnerable": false,
      "confidence": "high",
      "reason": "PQC key encapsulation mechanism; FIPS 203 standardized",
      "line_number": 11
    },
    {
      "algorithm": "ML-DSA-65",
      "quantum_vulnerable": false,
      "confidence": "high",
      "reason": "PQC digital signature; FIPS 204 standardized",
      "line_number": 15
    }
  ]
}
```

### 2.3 Homegrown Crypto Detection Prompt

**Input prompt:**
```
You are a cryptographic security expert specializing in detecting
non-standard and custom cryptographic implementations.

Analyze the code below. Look specifically for:
- Custom XOR-based encryption
- Homebrew block ciphers or stream ciphers
- Custom hash functions
- Feistel network implementations
- Any numeric operations that appear to implement crypto primitives

Return JSON ONLY:
{
  "homegrown_crypto_detected": true or false,
  "confidence": "high or medium or low",
  "description": "one sentence",
  "risk": "critical or high or medium or low",
  "recommendation": "one sentence remediation advice"
}

Code:
<code>
def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes([d ^ key[i % len(key)] for i, d in enumerate(data)])

def homebrew_block_cipher(block: bytes, rounds: int = 16) -> bytes:
    state = bytearray(block)
    for r in range(rounds):
        for i in range(len(state)):
            state[i] = ((state[i] * 7 + 11) ^ r) & 0xFF
    return bytes(state)
</code>
```

**Expected JSON response:**
```json
{
  "homegrown_crypto_detected": true,
  "confidence": "high",
  "description": "Custom XOR encryption and homebrew block cipher with linear operations",
  "risk": "critical",
  "recommendation": "Replace with standard authenticated encryption (AES-256-GCM or ChaCha20-Poly1305)"
}
```

### 2.4 No Crypto (Negative Test)

**Input prompt (content):**
```
<code>
def calculate_total(items):
    total = 0
    for item in items:
        total += item.price
    return total

def format_name(first, last):
    return f"{first} {last}".strip()
</code>
```

**Expected JSON response:**
```json
{
  "findings": []
}
```

### 2.5 SLM Hardening -- Adversarial Inputs

**File:** `samples/slm/adversarial_test_cases.py`

```python
"""Adversarial test cases for SLM crypto detection."""

# Test case 1: No crypto but with comment mentioning crypto
def fetch_data():
    # This uses RSA encryption internally (but actually does not - no crypto code here)
    response = requests.get("https://api.example.com/data")
    return response.json()

# Test case 2: Variable names that look like algorithms
rsa = "Road Signage Authority"
aes = "Advanced Energy Systems"
sha1 = "Safe Harbor Agreement 1.0"

# Test case 3: Base64 that resembles algorithm strings
config = {
    "algorithm": "AES-256-GCM-XTS",
    "cipher_mode": "XTS-CBC-CTS",
    "hash": "SHA-2-512-256",
}

# Test case 4: Misleading algorithm names
def my_crypto():
    """This isn't really crypto."""
    return {
        "rsa": 65537,          # Not RSA algorithm, just a number
        "curve": "P-256",      # Just a curve parameter name
        "hash": "SHA256",      # A configuration key, not a hash call
    }

# Test case 5: Real crypto mixed with noise
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = b'\x00' * 32
cipher = Cipher(algorithms.AES(key), modes.GCM(b'\x00' * 12))
```

---

## 3. CBOM Classifier -- Test Vectors

### 3.1 Full Algorithm Coverage Table

| Input Algorithm              | Expected Normalized | QuantumClass        | PQC Replacement     | NIST FIPS    |
|------------------------------|---------------------|---------------------|---------------------|--------------|
| `ML-KEM-512`                 | ML-KEM-512          | pqc                 | (none)              | FIPS 203     |
| `ML-KEM-768`                 | ML-KEM-768          | pqc                 | (none)              | FIPS 203     |
| `ML-KEM-1024`                | ML-KEM-1024         | pqc                 | (none)              | FIPS 203     |
| `ML-DSA-44`                  | ML-DSA-44           | pqc                 | (none)              | FIPS 204     |
| `ML-DSA-65`                  | ML-DSA-65           | pqc                 | (none)              | FIPS 204     |
| `ML-DSA-87`                  | ML-DSA-87           | pqc                 | (none)              | FIPS 204     |
| `SLH-DSA-SHAKE-128s`         | SLH-DSA             | pqc                 | (none)              | FIPS 205     |
| `SLH-DSA-SHAKE-192s`         | SLH-DSA             | pqc                 | (none)              | FIPS 205     |
| `SLH-DSA-SHAKE-256s`         | SLH-DSA             | pqc                 | (none)              | FIPS 205     |
| `FALCON-512`                 | FALCON              | pqc                 | (none)              | (none)       |
| `FALCON-1024`                | FALCON              | pqc                 | (none)              | (none)       |
| `Kyber-512` / `KYBER512`     | ML-KEM-512          | pqc                 | (none)              | FIPS 203     |
| `Kyber-768` / `KYBER768`     | ML-KEM-768          | pqc                 | (none)              | FIPS 203     |
| `Kyber-1024` / `KYBER1024`   | ML-KEM-1024         | pqc                 | (none)              | FIPS 203     |
| `Dilithium-2`                | ML-DSA-44           | pqc                 | (none)              | FIPS 204     |
| `Dilithium-3`                | ML-DSA-65           | pqc                 | (none)              | FIPS 204     |
| `Dilithium-5`                | ML-DSA-87           | pqc                 | (none)              | FIPS 204     |
| `SPHINCS+-128s`              | SLH-DSA             | pqc                 | (none)              | FIPS 205     |
| `RSA`                        | RSA                 | vulnerable          | ML-KEM-768          | FIPS 203     |
| `ECDSA`                      | ECDSA               | vulnerable          | ML-DSA-65           | FIPS 204     |
| `ECDH`                       | ECDH                | vulnerable          | ML-KEM-768          | FIPS 203     |
| `ED25519`                    | ED25519             | vulnerable          | ML-DSA-44           | FIPS 204     |
| `X25519`                     | X25519              | vulnerable          | ML-KEM-512          | FIPS 203     |
| `DH`                         | DH                  | vulnerable          | ML-KEM-768          | FIPS 203     |
| `DSA`                        | DSA                 | vulnerable          | ML-DSA-44           | FIPS 204     |
| `ElGamal`                    | ElGamal             | vulnerable          | ML-KEM-768          | FIPS 203     |
| `AES-128`                    | AES-128             | partially_safe      | AES-256             | (none)       |
| `AES-256`                    | AES-256             | safe                | (none)              | (none)       |
| `SHA-1`                      | SHA-1               | partially_safe      | SHA3-256            | (none)       |
| `SHA-256`                    | SHA-256             | partially_safe      | SHA3-256            | (none)       |
| `SHA-512`                    | SHA-512             | safe                | (none)              | (none)       |
| `GOST3410` (unknown)         | GOST3410            | unknown             | (none)              | (none)       |

### 3.2 Classifier Python Test Assertions

```python
"""Unit test assertions for PQC algorithm classification."""

def test_all_pqc_algorithms():
    """All PQC algorithms must map to QuantumClass.PQC."""
    pqc_algorithms = [
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "SLH-DSA", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-256s",
        "FALCON-512", "FALCON-1024",
        "KYBER512", "KYBER768", "KYBER1024",
        "DILITHIUM2", "DILITHIUM3", "DILITHIUM5",
        "SPHINCS", "SPHINCS+",
    ]
    for algo in pqc_algorithms:
        info = classify(algo)
        assert info.quantum_class == QuantumClass.PQC, f"{algo} should be PQC, got {info.quantum_class}"

def test_kyber_normalized_to_mlkem():
    """Pre-standard Kyber-768 should normalize to ML-KEM-768."""
    info = classify("KYBER768")
    assert info.normalized == "ML-KEM-768"
    assert info.nist_fips == "FIPS 203"

def test_dilithium_normalized_to_mldsa():
    """Pre-standard Dilithium-3 should normalize to ML-DSA-65."""
    info = classify("DILITHIUM3")
    assert info.normalized == "ML-DSA-65"
    assert info.nist_fips == "FIPS 204"

def test_sphincs_normalized_to_slhdsa():
    """SPHINCS+ should normalize to SLH-DSA."""
    info = classify("SPHINCS+")
    assert info.normalized == "SLH-DSA"
    assert info.nist_fips == "FIPS 205"

def test_falcon_no_nist_fips():
    """FALCON is not yet FIPS standardized."""
    info = classify("FALCON-512")
    assert info.quantum_class == QuantumClass.PQC
    assert info.nist_fips is None

def test_pqc_replacement_for_vulnerable():
    """Vulnerable algorithms must have a PQC replacement."""
    vuln_algos = ["RSA", "ECDSA", "DH", "DSA", "ED25519"]
    for algo in vuln_algos:
        info = classify(algo)
        assert info.quantum_class == QuantumClass.VULNERABLE
        assert info.pqc_replacement is not None, f"{algo} missing PQC replacement"

def test_pqc_replacement_nist_ref():
    """PQC replacements must reference a NIST FIPS number."""
    vuln_algos = ["RSA", "ECDSA", "DH", "DSA", "ED25519", "ECDH", "X25519"]
    for algo in vuln_algos:
        info = classify(algo)
        assert info.nist_fips is not None, f"{algo} missing NIST FIPS reference"
```

---

## 4. Zeek Network Sensor -- PQC Detection Patterns

### 4.1 Sample Zeek cbom_crypto.log Lines for PQC

```json
// Expected cbom_crypto.log entries for PQC hybrid key exchange
[
  {
    "ts": 1735000000.0,
    "uid": "CPQC1234abcd",
    "id.orig_h": "192.168.1.100",
    "id.orig_p": 54321,
    "id.resp_h": "10.0.0.1",
    "id.resp_p": 443,
    "protocol": "ssl",
    "algorithm": "ML-KEM-768",
    "key_size": 768,
    "crypto_type": "pqc_kem",
    "quantum_class": "pqc",
    "pqc_replace": "",
    "evidence": "TLS_MLKEM_768_X25519_WITH_AES_256_GCM_SHA384",
    "location": "pqc-demo.example.com:443"
  },
  {
    "ts": 1735000001.0,
    "uid": "CPQC1234abcd",
    "id.orig_h": "192.168.1.100",
    "id.orig_p": 54321,
    "id.resp_h": "10.0.0.1",
    "id.resp_p": 443,
    "protocol": "ssl",
    "algorithm": "ML-DSA-65",
    "key_size": 65,
    "crypto_type": "pqc_signature",
    "quantum_class": "pqc",
    "pqc_replace": "",
    "evidence": "TLS_MLKEM_768_X25519_WITH_AES_256_GCM_SHA384",
    "location": "pqc-demo.example.com:443"
  },
  {
    "ts": 1735000000.0,
    "uid": "CPQC5678efgh",
    "id.orig_h": "192.168.1.50",
    "id.orig_p": 55000,
    "id.resp_h": "10.0.0.5",
    "id.resp_p": 22,
    "protocol": "ssh",
    "algorithm": "ML-KEM-512",
    "key_size": 512,
    "crypto_type": "pqc_kem",
    "quantum_class": "pqc",
    "pqc_replace": "",
    "evidence": "mlkem512-sha256@openssh.com",
    "location": "pqc-ssh.example.com:22"
  }
]
```

### 4.2 Sample ssl.log for PQC Hybrid Cipher Suites

```json
{
  "ts": 1735000000.0,
  "uid": "CPQC1234abcd",
  "id.orig_h": "192.168.1.100",
  "id.orig_p": 54321,
  "id.resp_h": "10.0.0.1",
  "id.resp_p": 443,
  "version": "TLSv13",
  "cipher": "TLS_AES_256_GCM_SHA384",
  "curve": "x25519+ML-KEM-768",
  "server_name": "pqc-demo.example.com",
  "resumed": false,
  "established": true,
  "cert_alg": "ML-DSA-65",
  "cert_chain_fuids": ["FpqcAAAAA"],
  "client_cert_chain_fuids": []
}
```

### 4.3 Sample x509.log for PQC Certificate

```json
{
  "ts": 1735000000.0,
  "id": "FpqcAAAAA",
  "certificate.version": 3,
  "certificate.serial": "PQ:CA:01:23:45",
  "certificate.subject": "CN=pqc-demo.example.com,O=PQC Corp",
  "certificate.issuer": "CN=Hybrid Root CA",
  "certificate.not_valid_before": 1700000000.0,
  "certificate.not_valid_after": 1830000000.0,
  "certificate.key_alg": "id-MLKEM768",
  "certificate.sig_alg": "id-MLDSA65",
  "certificate.key_type": "ml-kem-768",
  "certificate.key_length": 768
}
```

### 4.4 Zeek Crypto Detection Script Test Cases

```
# Test scenario: PQC hybrid TLS handshake
# Zeek should write TWO cbom_crypto.log lines:
#   1. algorithm=ML-KEM-768, crypto_type=pqc_kem
#   2. algorithm=ML-DSA-65,  crypto_type=pqc_signature
#
# Cipher:  TLS_CHACHA20_POLY1305_SHA256
# Curve:   x25519+MLKEM768
# Cert:    ML-DSA-65 signed

# To test with a pcap:
#   zeek -r pqc_handshake.pcap local /zeek/scripts/crypto-detection.zeek
#   cat cbom_crypto.log | python3 -m json.tool
```

---

## 5. QARS / QSRI -- PQC Score Test Vectors

### 5.1 Complete Scan Result Example

```json
{
  "scan_id": "pqc-demo-scan-001",
  "scan_name": "PQC Demo Application Scan",
  "sector": "general_enterprise",
  "q_day_year": 2030,
  "timestamp": "2025-06-01T00:00:00Z",
  "status": "complete",
  "summary": {
    "total_assets": 8,
    "vulnerable_count": 4,
    "partially_safe_count": 1,
    "safe_count": 1,
    "pqc_count": 2,
    "unknown_count": 0,
    "critical_findings": 1,
    "high_findings": 3,
    "medium_findings": 1,
    "low_findings": 1
  },
  "assets": [
    {
      "id": "ast-001",
      "algorithm": "RSA",
      "key_size": 2048,
      "quantum_class": "vulnerable",
      "location": "web-app/certs/server.key",
      "source": "cert_scanner",
      "data_classification": "internal"
    },
    {
      "id": "ast-002",
      "algorithm": "ECDSA",
      "key_size": 256,
      "quantum_class": "vulnerable",
      "location": "web-app/src/auth.js",
      "source": "ast_scanner",
      "data_classification": "internal"
    },
    {
      "id": "ast-003",
      "algorithm": "DH",
      "key_size": 2048,
      "quantum_class": "vulnerable",
      "location": "sample-db:5432",
      "source": "zeek_network",
      "data_classification": "restricted"
    },
    {
      "id": "ast-004",
      "algorithm": "MD5",
      "key_size": 128,
      "quantum_class": "partially_safe",
      "location": "db-service/init.sql",
      "source": "ast_scanner",
      "data_classification": "public"
    },
    {
      "id": "ast-005",
      "algorithm": "SHA-1",
      "key_size": null,
      "quantum_class": "partially_safe",
      "location": "cert-validator/hash_utils.py",
      "source": "ast_scanner",
      "data_classification": "internal"
    },
    {
      "id": "ast-006",
      "algorithm": "AES-256",
      "key_size": 256,
      "quantum_class": "safe",
      "location": "web-app/src/crypto.py",
      "source": "ast_scanner",
      "data_classification": "internal"
    },
    {
      "id": "ast-007",
      "algorithm": "ML-KEM-768",
      "key_size": null,
      "quantum_class": "pqc",
      "location": "web-app/src/kem.py",
      "source": "ast_scanner",
      "data_classification": "restricted"
    },
    {
      "id": "ast-008",
      "algorithm": "ML-DSA-65",
      "key_size": null,
      "quantum_class": "pqc",
      "location": "web-app/src/sign.py",
      "source": "ast_scanner",
      "data_classification": "restricted"
    }
  ],
  "qsri_score": {
    "total_score": 42.5,
    "dimension_scores": {
      "inventory": 60.0,
      "vulnerability_analysis": 40.0,
      "intrusion_detection": 20.0,
      "incident_response": 40.0,
      "access_control": 60.0,
      "encryption_management": 60.0,
      "supply_chain": 20.0,
      "compliance": 40.0
    },
    "recommendations": [
      {"dimension": "intrusion_detection", "impact": "high", "score_gain": 30.0},
      {"dimension": "supply_chain", "impact": "high", "score_gain": 25.0},
      {"dimension": "vulnerability_analysis", "impact": "high", "score_gain": 20.0}
    ]
  },
  "qars_results": [
    {
      "asset_id": "ast-003",
      "algorithm": "DH",
      "base_qars": 1.0,
      "weighted_qars": 3.0,
      "severity": "critical",
      "mosca_urgent": true,
      "x_value": 10,
      "y_value": 3,
      "z_value": 5,
      "exposure_factor": 1.5,
      "sensitivity_weight": 2.0
    },
    {
      "asset_id": "ast-001",
      "algorithm": "RSA",
      "base_qars": 1.0,
      "weighted_qars": 1.0,
      "severity": "critical",
      "mosca_urgent": true,
      "x_value": 10,
      "y_value": 3,
      "z_value": 5,
      "exposure_factor": 1.0,
      "sensitivity_weight": 1.0
    },
    {
      "asset_id": "ast-002",
      "algorithm": "ECDSA",
      "base_qars": 0.6,
      "weighted_qars": 0.6,
      "severity": "high",
      "mosca_urgent": true,
      "x_value": 10,
      "y_value": 3,
      "z_value": 5,
      "exposure_factor": 1.0,
      "sensitivity_weight": 1.0
    },
    {
      "asset_id": "ast-004",
      "algorithm": "MD5",
      "base_qars": 0.0,
      "weighted_qars": 0.0,
      "severity": "low",
      "mosca_urgent": false,
      "x_value": 10,
      "y_value": 3,
      "z_value": 5,
      "exposure_factor": 1.0,
      "sensitivity_weight": 1.0
    },
    {
      "asset_id": "ast-007",
      "algorithm": "ML-KEM-768",
      "base_qars": 0.0,
      "weighted_qars": 0.0,
      "severity": "low",
      "mosca_urgent": false,
      "x_value": 10,
      "y_value": 3,
      "z_value": 5,
      "exposure_factor": 1.5,
      "sensitivity_weight": 2.0
    },
    {
      "asset_id": "ast-008",
      "algorithm": "ML-DSA-65",
      "base_qars": 0.0,
      "weighted_qars": 0.0,
      "severity": "low",
      "mosca_urgent": false,
      "x_value": 10,
      "y_value": 3,
      "z_value": 5,
      "exposure_factor": 1.5,
      "sensitivity_weight": 2.0
    }
  ]
}
```

### 5.2 Mosca Inequality Test Vectors

```
Mosca Inequality:  (X + Y) >= Z  =>  Migrate urgently

Where:
  X = years to quantum-safe migration (sector default: 10)
  Y = years to migrate current system (sector default: 3)
  Z = years until Q-Day (2030 - 2025 = 5)

Scenario A: Q-Day 2030 (Z=5)
  X=10, Y=3, Z=5  -> 13 >= 5  -> URGENT
  Scoring: vulnerable assets get base_qars=1.0

Scenario B: Q-Day 2035 (Z=10)
  X=10, Y=3, Z=10 -> 13 >= 10 -> URGENT
  Scoring: base_qars = (X+Y)/Z = 13/10 = 1.3 -> clamped to 1.0

Scenario C: Q-Day 2040 (Z=15)
  X=10, Y=3, Z=15 -> 13 >= 15 -> NOT urgent
  Scoring: base_qars = 13/15 = 0.87

Scenario D: PQC asset
  X=10, Y=3, Z=5  -> base_qars = 0.0 (always zero for PQC/safe)
```

---

## 6. End-to-End Test Prompts

### 6.1 Full PQC E2E Test

```python
# tests/e2e/test_pqc_scan_flow.py
"""E2E test: scan a PQC-enabled app and verify CBOM has PQC assets."""
import os, time, json
import httpx

BASE_URL = os.environ.get("E2E_BASE_URL", "https://localhost")
ADMIN_EMAIL = os.environ.get("E2E_ADMIN_EMAIL", "admin@cbom.local")
ADMIN_PASS  = os.environ.get("E2E_ADMIN_PASS", "AdminPass123!")


def get_token() -> str:
    resp = httpx.post(f"{BASE_URL}/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASS},
        verify=False, timeout=30)
    resp.raise_for_status()
    return resp.json()["access_token"]


def test_pqc_scan_discovers_mlkem(token: str):
    """Scan a PQC-enabled target and verify ML-KEM is found."""
    headers = {"Authorization": f"Bearer {token}"}

    # Create scan targeting PQC demo app
    resp = httpx.post(f"{BASE_URL}/api/scans",
        json={
            "name": "PQC Demo App Scan",
            "target_hosts": ["pqc-demo:8443"],
            "target_files": ["/samples/pqc/"],
            "sector": "general_enterprise",
            "q_day_year": 2030,
        },
        headers=headers, verify=False, timeout=30)
    assert resp.status_code == 201
    scan_id = resp.json()["scan_id"]

    # Poll until complete
    for _ in range(60):
        sr = httpx.get(f"{BASE_URL}/api/scans/{scan_id}",
            headers=headers, verify=False, timeout=10)
        status = sr.json().get("status")
        if status in ("complete", "failed"):
            break
        time.sleep(5)

    assert status == "complete", f"Scan failed with status: {status}"

    # Verify PQC assets were found
    assets_resp = httpx.get(f"{BASE_URL}/api/assets",
        params={"scan_id": scan_id, "limit": 100},
        headers=headers, verify=False, timeout=10)
    assets = assets_resp.json().get("items", [])

    pqc_assets = [a for a in assets if a.get("quantum_class") == "pqc"]
    assert len(pqc_assets) > 0, "No PQC assets found!"

    pqc_algos = {a["algorithm"] for a in pqc_assets}
    print(f"PQC assets found: {pqc_algos}")

    # Verify specific PQC algorithms
    assert any("ML-KEM" in a.upper() for a in pqc_algos), "ML-KEM not detected"

    # Verify QARS score is 0 for PQC assets
    qars_resp = httpx.get(f"{BASE_URL}/api/qars",
        params={"scan_id": scan_id},
        headers=headers, verify=False, timeout=10)
    qars_results = qars_resp.json().get("results", [])

    for r in qars_results:
        if r["asset"]["quantum_class"] == "pqc":
            assert r["weighted_qars"] == 0.0, \
                f"PQC asset {r['asset']['algorithm']} should score 0, got {r['weighted_qars']}"

    # Verify CBOM export includes PQC components
    cbom_resp = httpx.get(f"{BASE_URL}/api/cbom/{scan_id}/export",
        headers=headers, verify=False, timeout=30)
    cbom = cbom_resp.json()
    pqc_components = [
        c for c in cbom.get("components", [])
        if any(p.get("value") == "pqc" for p in c.get("properties", [])
               if p.get("name") == "cbom:quantumClass")
    ]
    assert len(pqc_components) > 0, "No PQC components in CBOM export"
```

### 6.2 E2E Test: PQC vs Vulnerable Classification

```python
def test_pqc_classification_accuracy(token: str):
    """Verify every discovered asset has correct quantum_class."""
    headers = {"Authorization": f"Bearer {token}"}

    resp = httpx.get(f"{BASE_URL}/api/assets",
        params={"limit": 1000},
        headers=headers, verify=False, timeout=30)
    assets = resp.json().get("items", [])

    # Known classifications to verify
    expected = {
        "ML-KEM-512": "pqc",
        "ML-KEM-768": "pqc",
        "ML-KEM-1024": "pqc",
        "ML-DSA-44": "pqc",
        "ML-DSA-65": "pqc",
        "ML-DSA-87": "pqc",
        "SLH-DSA": "pqc",
        "FALCON": "pqc",
        "RSA": "vulnerable",
        "ECDSA": "vulnerable",
        "ECDH": "vulnerable",
        "DH": "vulnerable",
        "ED25519": "vulnerable",
        "DSA": "vulnerable",
    }

    errors = []
    for asset in assets:
        algo = asset.get("algorithm", "").upper()
        expected_class = expected.get(algo)
        if expected_class is not None:
            actual_class = asset.get("quantum_class")
            if actual_class != expected_class:
                errors.append(
                    f"{algo}: expected {expected_class}, got {actual_class}"
                )

    assert len(errors) == 0, f"Classification errors:\n" + "\n".join(errors)
```

---

## 7. Traffic Sim PQC Scenario -- Test Data

### 7.1 pqc_demo.py Scenario Input Map

```python
"""Transit map: PQC demo scenario - expected inputs/outputs."""

# Expected planted crypto assets for the PQC demo
PQC_PLANTED_ASSETS = [
    {"algorithm": "ML-KEM-768", "location": "pqc-demo",   "key_size": 768, "source": "ast_scanner"},
    {"algorithm": "ML-DSA-65",  "location": "pqc-demo",   "key_size": 65,  "source": "ast_scanner"},
    {"algorithm": "RSA",        "location": "pqc-demo",   "key_size": 2048,"source": "cert_scanner"},
    {"algorithm": "X25519",     "location": "pqc-demo",   "key_size": 256, "source": "zeek_network"},
    {"algorithm": "AES-256",    "location": "pqc-demo",   "key_size": 256, "source": "zeek_network"},
    {"algorithm": "ChaCha20-Poly1305","location":"pqc-demo", "key_size":256,"source":"zeek_network"},
]

# Expected coverage benchmark results
EXPECTED_COVERAGE = {
    "planted_count": 6,
    "discovered_count": ">= 4",
    "coverage_pct": ">= 66%",
    "grade": "B or better",
}
```

### 7.2 Locustfile PQC Scenario

```python
"""Locust scenario: PQC hybrid key exchange traffic."""
from locust import HttpUser, task, between
import ssl
import urllib.request


class PQCUser(HttpUser):
    wait_time = between(1, 3)
    abstract = True  # Don't run directly

    def on_start(self):
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE


class PQCWebUser(PQCUser):
    """Simulate HTTPS traffic with PQC hybrid key exchange."""

    @task(3)
    def access_pqc_endpoint(self):
        """Send request to PQC demo web app."""
        try:
            with urllib.request.urlopen(
                "https://pqc-demo:8443/",
                context=self.ctx,
                timeout=10
            ) as resp:
                _ = resp.read()
        except Exception:
            pass

    @task(1)
    def call_pqc_api(self):
        """Call PQC demo REST endpoint."""
        try:
            with urllib.request.urlopen(
                "https://pqc-demo:8443/api/pqc/status",
                context=self.ctx,
                timeout=10
            ) as resp:
                data = resp.read()
        except Exception:
            pass
```

---

## 8. Quick-Reference: PQC Test Data Files

Create the following file structure for automated test execution:

```
samples/pqc/                              # PQC source code samples (AST scanner)
├── pqc_key_encaps.py                     # ML-KEM-768 example
├── pqc_signatures.py                     # ML-DSA-65 + SLH-DSA example
├── hybrid_kex.py                         # ECDHE + ML-KEM hybrid
├── falcon_sign.py                        # FALCON example
├── kyber_legacy.py                       # Pre-standard Kyber
├── dilithium_legacy.py                   # Pre-standard Dilithium
├── classical_vulnerable.py               # Contrast: classical vulnerable
├── go_pqc.go                             # Go PQC with circl
├── JavaPQC.java                          # Java PQC with Bouncy Castle
└── ts_pqc.ts                             # TypeScript PQC with pqcrypto

samples/zeek/                             # Zeek log samples
└── pqc_cbom_crypto.json                  # Expected Zeek cbom_crypto.log entries

samples/slm/                              # SLM prompt samples
├── adversarial_test_cases.py             # Adversarial/edge case code
├── pqc_prompt_example.txt                # SLM prompt + expected response
└── homegrown_crypto_prompt.txt           # Homegrown crypto detection prompt

samples/e2e/                              # E2E test samples
└── pqc_scan_result.json                  # Expected full scan result
```

---

## 9. CBOM CycloneDX 1.6 PQC Component Example

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:a1b2c3d4-1234-5678-9abc-def012345678",
  "version": 1,
  "metadata": {
    "timestamp": "2025-06-01T12:00:00Z",
    "tools": [{"vendor": "CBOM Platform", "name": "CBOM Discovery Platform", "version": "1.0.0-mvp"}],
    "properties": [{"name": "cbom:scanId", "value": "scan-pqc-001"}]
  },
  "components": [
    {
      "type": "cryptographic-asset",
      "bom-ref": "4a3b2c1d-5678-90ab-cdef-012345678901",
      "name": "ML-KEM-768",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "pke",
          "parameterSetIdentifier": "768",
          "executionEnvironment": "software-plain-ram",
          "cryptoFunctions": ["encapsulate", "decapsulate"],
          "nistQuantumSecurityLevel": 3
        }
      },
      "evidence": {
        "occurrences": [
          {"location": "web-app/src/kem.py", "line": 4}
        ]
      },
      "properties": [
        {"name": "cbom:quantumClass",    "value": "pqc"},
        {"name": "cbom:pqcReplacement",  "value": "none"},
        {"name": "cbom:nistFips",         "value": "FIPS 203"},
        {"name": "cbom:reason",           "value": "Module-Lattice KEM; NIST standardized"},
        {"name": "cbom:discoverySource",  "value": "ast_scanner"},
        {"name": "cbom:confidence",       "value": "high"}
      ]
    },
    {
      "type": "cryptographic-asset",
      "bom-ref": "5c4d3e2f-6789-01ab-cdef-012345678902",
      "name": "ML-DSA-65",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "signature",
          "parameterSetIdentifier": "65",
          "executionEnvironment": "software-plain-ram",
          "cryptoFunctions": ["sign", "verify"],
          "nistQuantumSecurityLevel": 3
        }
      },
      "evidence": {
        "occurrences": [
          {"location": "web-app/src/sign.py", "line": 6}
        ]
      },
      "properties": [
        {"name": "cbom:quantumClass",    "value": "pqc"},
        {"name": "cbom:pqcReplacement",  "value": "none"},
        {"name": "cbom:nistFips",         "value": "FIPS 204"},
        {"name": "cbom:reason",           "value": "Module-Lattice DSA; NIST standardized"},
        {"name": "cbom:discoverySource",  "value": "ast_scanner"},
        {"name": "cbom:confidence",       "value": "high"}
      ]
    },
    {
      "type": "cryptographic-asset",
      "bom-ref": "6d5e4f3g-7890-12ab-cdef-012345678903",
      "name": "RSA",
      "cryptoProperties": {
        "assetType": "algorithm",
        "algorithmProperties": {
          "primitive": "pke",
          "parameterSetIdentifier": "2048",
          "executionEnvironment": "software-plain-ram",
          "cryptoFunctions": ["encrypt", "decrypt"],
          "nistQuantumSecurityLevel": 0
        }
      },
      "evidence": {
        "occurrences": [
          {"location": "web-app/certs/server.key", "line": null}
        ]
      },
      "properties": [
        {"name": "cbom:quantumClass",    "value": "vulnerable"},
        {"name": "cbom:pqcReplacement",  "value": "ML-KEM-768"},
        {"name": "cbom:nistFips",         "value": "FIPS 203"},
        {"name": "cbom:reason",           "value": "Shor's algorithm factors RSA modulus in polynomial time"},
        {"name": "cbom:discoverySource",  "value": "cert_scanner"},
        {"name": "cbom:confidence",       "value": "high"}
      ]
    }
  ]
}
```

---

## 10. Summary: PQC Test Prompt Coverage Map

| Detection Layer         | What It Tests                                          | Key File(s)                         |
|-------------------------|--------------------------------------------------------|-------------------------------------|
| AST Scanner (Python)    | ML-KEM, ML-DSA, FALCON, Kyber, Dilithium, SLH-DSA     | `samples/pqc/*.py`                  |
| AST Scanner (Go)        | Kyber768, Dilithium3 via cloudflare/circl              | `samples/pqc/go_pqc.go`            |
| AST Scanner (Java)      | ML-KEM, ML-DSA via Bouncy Castle PQC                   | `samples/pqc/JavaPQC.java`         |
| AST Scanner (TypeScript)| ML-KEM, ML-DSA via pqcrypto npm                        | `samples/pqc/ts_pqc.ts`            |
| SLM/llama.cpp           | Prompt parsing, JSON structure, crypto detection       | `samples/slm/*.txt`                |
| SLM Adversarial         | False positives, variable names, no-crypto edge cases  | `samples/slm/adversarial_test_cases.py` |
| Classifier              | All 60+ algorithm entries, normalization, NIST refs   | (in spec 07) + section 3 above     |
| Zeek Network Sensor     | PQC hybrid cipher suites, ML-DSA certs, cbom_crypto   | `samples/zeek/pqc_cbom_crypto.json` |
| QARS Engine             | PQC assets score 0, Mosca inequality, vulnerability scoring | (in spec 08) + section 5 above |
| QSRI Engine             | Inventory coverage auto-population, dimension scoring  | (in spec 08)                        |
| Findings Generator      | Severity mapping, compliance gaps (DORA/NIS2/NSM-10)  | (in spec 07)                        |
| CBOM Export (CDX 1.6)   | PQC component structure, properties, evidence          | Section 9 above                     |
| E2E Scan Flow           | Full pipeline: create scan -> discover PQC -> verify   | `tests/e2e/test_pqc_scan_flow.py`  |
| Traffic Sim PQC Demo    | Hybrid ML-KEM+ECDH traffic generation                  | `scenarios/pqc_demo.py`            |
| Coverage Benchmark      | Planted vs discovered PQC assets                       | `benchmark/coverage_report.py`      |