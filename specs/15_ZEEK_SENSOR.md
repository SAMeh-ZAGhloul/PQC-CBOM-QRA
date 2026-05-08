# 15 -- Zeek Network Sensor

> Read `00_MASTER_SPEC.md`, `09_ORCHESTRATOR.md` first.

---

## Overview

Zeek 6.x runs in **host network mode** with `NET_RAW` and `NET_ADMIN`
capabilities, enabling passive capture of all network traffic on the
host interface. It writes structured JSON logs to a shared Docker volume
that the orchestrator's log watcher monitors in real time.

Zeek is **read-only** -- it never modifies traffic or injects packets.

---

## Directory Structure

```
zeek/
├── local.zeek                     # Site policy: which scripts to load
└── scripts/
    └── crypto-detection.zeek      # Cipher suite -> algorithm classification
```

---

## zeek/local.zeek

```zeek
##! CBOM Platform -- Zeek site policy
##! Loads standard crypto-relevant analyzers and enables JSON output.

# ── Standard protocol analyzers ──────────────────────────────────────────
@load protocols/ssl            # TLS/SSL: cipher suites, certificates, versions
@load protocols/ssl/heartbleed # Heartbleed detection
@load protocols/ssl/known-certs # Known certificate tracking
@load protocols/ssh            # SSH: key exchange, host key algorithms
@load protocols/http           # HTTP (for plaintext crypto references)

# ── File analysis framework ───────────────────────────────────────────────
@load frameworks/files/hash    # Hash all files: MD5, SHA-1, SHA-256
@load frameworks/files/extract # Extract files for deeper analysis (optional)

# ── Certificate logging ───────────────────────────────────────────────────
@load policy/protocols/ssl/log-hostcerts-only   # Log only host certs (not intermediates)

# ── Custom crypto detection ───────────────────────────────────────────────
@load ./scripts/crypto-detection

# ── JSON output (required for orchestrator parsing) ───────────────────────
@load tuning/json-logs

# ── Log rotation: rotate every hour ──────────────────────────────────────
redef Log::default_rotation_interval = 1hr;
redef Log::default_rotation_postprocessor_cmd = "";

# ── File hashing configuration ───────────────────────────────────────────
redef FileExtract::prefix = "/zeek/logs/extracted/";

event zeek_init()
    {
    print "CBOM Zeek sensor started -- crypto detection active";
    }
```

---

## zeek/scripts/crypto-detection.zeek

```zeek
##! CBOM Crypto Detection Script
##! Extends Zeek's SSL/SSH logging with quantum vulnerability classifications.

module CBOMCrypto;

export {
    ## Log stream identifier
    redef enum Log::ID += { LOG };

    ## Record written to cbom_crypto.log
    type Info: record {
        ts:            time    &log;
        uid:           string  &log;
        id:            conn_id &log;
        protocol:      string  &log;           # ssl, ssh
        algorithm:     string  &log;           # detected algorithm name
        key_size:      count   &log &optional; # key size in bits
        crypto_type:   string  &log;           # key_exchange, symmetric, hash, signature
        quantum_class: string  &log;           # vulnerable, partially_safe, safe, pqc
        pqc_replace:   string  &log &optional; # recommended PQC replacement
        evidence:      string  &log;           # raw cipher suite or key algo string
        location:      string  &log;           # server_name or ip:port
    };

    global log_cbom_crypto: event(rec: Info);
}

# ── Quantum classification tables ─────────────────────────────────────────

## Cipher suite -> (algorithm, key_size, crypto_type, quantum_class, pqc_replacement)
const CIPHER_SUITE_MAP: table[string] of vector of string = {
    # TLS 1.3 cipher suites (quantum-safe symmetric, but key exchange matters)
    ["TLS_AES_256_GCM_SHA384"]           = vector("AES-256", "256", "symmetric_encryption", "safe", ""),
    ["TLS_CHACHA20_POLY1305_SHA256"]     = vector("ChaCha20-Poly1305", "256", "symmetric_encryption", "safe", ""),
    ["TLS_AES_128_GCM_SHA256"]           = vector("AES-128", "128", "symmetric_encryption", "partially_safe", "AES-256"),

    # RSA key exchange (vulnerable)
    ["TLS_RSA_WITH_AES_256_GCM_SHA384"]  = vector("RSA", "2048", "key_exchange", "vulnerable", "ML-KEM-768"),
    ["TLS_RSA_WITH_AES_256_CBC_SHA256"]  = vector("RSA", "2048", "key_exchange", "vulnerable", "ML-KEM-768"),
    ["TLS_RSA_WITH_AES_128_CBC_SHA"]     = vector("RSA", "2048", "key_exchange", "vulnerable", "ML-KEM-768"),
    ["TLS_RSA_WITH_AES_128_GCM_SHA256"]  = vector("RSA", "2048", "key_exchange", "vulnerable", "ML-KEM-768"),

    # ECDHE key exchange (vulnerable)
    ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]   = vector("ECDH", "256", "key_exchange", "vulnerable", "ML-KEM-768"),
    ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"]   = vector("ECDH", "256", "key_exchange", "vulnerable", "ML-KEM-768"),
    ["TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305"]    = vector("ECDH", "256", "key_exchange", "vulnerable", "ML-KEM-768"),
    ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"] = vector("ECDSA", "256", "digital_signature", "vulnerable", "ML-DSA-65"),
    ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"] = vector("ECDSA", "256", "digital_signature", "vulnerable", "ML-DSA-65"),

    # DHE key exchange (vulnerable)
    ["TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"] = vector("DH", "2048", "key_exchange", "vulnerable", "ML-KEM-768"),
    ["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"] = vector("DH", "2048", "key_exchange", "vulnerable", "ML-KEM-768"),

    # Weak / broken (critical)
    ["TLS_RSA_WITH_RC4_128_SHA"]         = vector("RC4", "128", "symmetric_encryption", "partially_safe", "AES-256-GCM"),
    ["TLS_RSA_WITH_RC4_128_MD5"]         = vector("RC4", "128", "symmetric_encryption", "partially_safe", "AES-256-GCM"),
    ["TLS_RSA_WITH_DES_CBC_SHA"]         = vector("DES", "56", "symmetric_encryption", "partially_safe", "AES-256"),
    ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"]    = vector("3DES", "168", "symmetric_encryption", "partially_safe", "AES-256"),
    ["TLS_ECDHE_RSA_WITH_RC4_128_SHA"]   = vector("RC4", "128", "symmetric_encryption", "partially_safe", "AES-256-GCM"),
} &default = vector("UNKNOWN", "0", "unknown", "unknown", "");


## SSH key exchange algorithm -> (algorithm, key_size, quantum_class, pqc_replacement)
const SSH_KEXALG_MAP: table[string] of vector of string = {
    ["curve25519-sha256"]                = vector("X25519", "256", "vulnerable", "ML-KEM-512"),
    ["curve25519-sha256@libssh.org"]     = vector("X25519", "256", "vulnerable", "ML-KEM-512"),
    ["ecdh-sha2-nistp256"]               = vector("ECDH", "256", "vulnerable", "ML-KEM-768"),
    ["ecdh-sha2-nistp384"]               = vector("ECDH", "384", "vulnerable", "ML-KEM-768"),
    ["ecdh-sha2-nistp521"]               = vector("ECDH", "521", "vulnerable", "ML-KEM-768"),
    ["diffie-hellman-group14-sha256"]    = vector("DH", "2048", "vulnerable", "ML-KEM-768"),
    ["diffie-hellman-group14-sha1"]      = vector("DH", "2048", "vulnerable", "ML-KEM-768"),
    ["diffie-hellman-group1-sha1"]       = vector("DH", "1024", "vulnerable", "ML-KEM-768"),
    ["diffie-hellman-group-exchange-sha256"] = vector("DH", "2048", "vulnerable", "ML-KEM-768"),
    ["diffie-hellman-group16-sha512"]    = vector("DH", "4096", "vulnerable", "ML-KEM-768"),
} &default = vector("DH", "0", "vulnerable", "ML-KEM-768");


## SSH host key algorithm -> (algorithm, key_size, quantum_class, pqc_replacement)
const SSH_HOSTKEY_MAP: table[string] of vector of string = {
    ["ssh-rsa"]              = vector("RSA", "2048", "vulnerable", "ML-DSA-65"),
    ["rsa-sha2-256"]         = vector("RSA", "2048", "vulnerable", "ML-DSA-65"),
    ["rsa-sha2-512"]         = vector("RSA", "4096", "vulnerable", "ML-DSA-65"),
    ["ecdsa-sha2-nistp256"]  = vector("ECDSA", "256", "vulnerable", "ML-DSA-65"),
    ["ecdsa-sha2-nistp384"]  = vector("ECDSA", "384", "vulnerable", "ML-DSA-65"),
    ["ecdsa-sha2-nistp521"]  = vector("ECDSA", "521", "vulnerable", "ML-DSA-65"),
    ["ssh-ed25519"]          = vector("ED25519", "256", "vulnerable", "ML-DSA-44"),
    ["sk-ssh-ed25519@openssh.com"] = vector("ED25519", "256", "vulnerable", "ML-DSA-44"),
    ["ssh-dss"]              = vector("DSA", "1024", "vulnerable", "ML-DSA-44"),
} &default = vector("RSA", "2048", "vulnerable", "ML-DSA-65");


# ── Log stream init ────────────────────────────────────────────────────────

event zeek_init() &priority=5
    {
    Log::create_stream(CBOMCrypto::LOG, [$columns=Info, $path="cbom_crypto"]);
    }


# ── SSL/TLS cipher suite handler ──────────────────────────────────────────

event ssl_established(c: connection)
    {
    if ( ! c?$ssl ) return;
    if ( ! c$ssl?$cipher ) return;

    local cipher = c$ssl$cipher;
    local fields = CIPHER_SUITE_MAP[cipher];
    local algo   = fields[0];
    local ksz    = to_count(fields[1]);
    local ctype  = fields[2];
    local qclass = fields[3];
    local pqc    = fields[4];

    local server_name = "";
    if ( c$ssl?$server_name )
        server_name = c$ssl$server_name;

    local location = fmt("%s:%s", c$id$resp_h, c$id$resp_p);
    if ( server_name != "" )
        location = fmt("%s:%s", server_name, c$id$resp_p);

    Log::write(CBOMCrypto::LOG, Info(
        $ts           = network_time(),
        $uid          = c$uid,
        $id           = c$id,
        $protocol     = "ssl",
        $algorithm    = algo,
        $key_size     = ksz,
        $crypto_type  = ctype,
        $quantum_class= qclass,
        $pqc_replace  = pqc,
        $evidence     = cipher,
        $location     = location,
    ));

    # Also log TLS version if it's a legacy version
    if ( c$ssl?$version )
        {
        local ver = c$ssl$version;
        if ( ver == "TLSv10" || ver == "TLSv11" )
            Log::write(CBOMCrypto::LOG, Info(
                $ts           = network_time(),
                $uid          = c$uid,
                $id           = c$id,
                $protocol     = "ssl",
                $algorithm    = fmt("TLS-%s", ver),
                $crypto_type  = "key_exchange",
                $quantum_class= "partially_safe",
                $pqc_replace  = "TLS-1.3",
                $evidence     = ver,
                $location     = location,
            ));
        }
    }


# ── X.509 certificate handler ─────────────────────────────────────────────

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
    {
    local key_type = cert$key_type;
    local key_len  = cert$key_length;

    local algo       = "UNKNOWN";
    local ctype      = "asymmetric_encryption";
    local qclass     = "vulnerable";
    local pqc        = "ML-KEM-768";

    if ( key_type == "rsa" )
        { algo = "RSA"; pqc = "ML-DSA-65"; ctype = "digital_signature"; }
    else if ( key_type == "ecdsa" || key_type == "ec" )
        { algo = "ECDSA"; pqc = "ML-DSA-65"; ctype = "digital_signature"; }
    else if ( key_type == "dsa" )
        { algo = "DSA"; pqc = "ML-DSA-44"; ctype = "digital_signature"; }
    else if ( key_type == "ed25519" )
        { algo = "ED25519"; pqc = "ML-DSA-44"; ctype = "digital_signature"; }

    # Approximate location from file source
    local location = fmt("cert:%s", cert$subject);
    if ( |location| > 100 )
        location = location[0:100];

    Log::write(CBOMCrypto::LOG, Info(
        $ts           = network_time(),
        $uid          = fmt("x509-%s", sha1_hash(cert$subject + cert$issuer)),
        $id           = [$orig_h=0.0.0.0, $orig_p=0/tcp, $resp_h=0.0.0.0, $resp_p=0/tcp],
        $protocol     = "x509",
        $algorithm    = algo,
        $key_size     = key_len,
        $crypto_type  = ctype,
        $quantum_class= qclass,
        $pqc_replace  = pqc,
        $evidence     = fmt("%s %d-bit cert for %s", key_type, key_len, cert$subject[0:60]),
        $location     = location,
    ));
    }


# ── SSH key exchange handler ──────────────────────────────────────────────

event ssh_server_host_key(c: connection, algo: string, key: string)
    {
    local fields = SSH_HOSTKEY_MAP[algo];
    local location = fmt("%s:%s", c$id$resp_h, c$id$resp_p);

    Log::write(CBOMCrypto::LOG, Info(
        $ts           = network_time(),
        $uid          = c$uid,
        $id           = c$id,
        $protocol     = "ssh",
        $algorithm    = fields[0],
        $key_size     = to_count(fields[1]),
        $crypto_type  = "digital_signature",
        $quantum_class= fields[2],
        $pqc_replace  = fields[3],
        $evidence     = algo,
        $location     = location,
    ));
    }


event ssh_capabilities(c: connection, remote_side: count, capabilities: SSH::Capabilities)
    {
    if ( remote_side != SSH::SERVER ) return;
    local location = fmt("%s:%s", c$id$resp_h, c$id$resp_p);

    # Key exchange algorithms
    for ( kex_algo in capabilities$kex_algorithms )
        {
        local kex_fields = SSH_KEXALG_MAP[kex_algo];
        Log::write(CBOMCrypto::LOG, Info(
            $ts           = network_time(),
            $uid          = c$uid,
            $id           = c$id,
            $protocol     = "ssh",
            $algorithm    = kex_fields[0],
            $key_size     = to_count(kex_fields[1]),
            $crypto_type  = "key_exchange",
            $quantum_class= kex_fields[2],
            $pqc_replace  = kex_fields[3],
            $evidence     = kex_algo,
            $location     = location,
        ));
        }
    }
```

---

## Expected Log Output Formats

### ssl.log (standard Zeek JSON)
```json
{
  "ts": 1735000000.0,
  "uid": "CnAbbL1234abcd",
  "id.orig_h": "192.168.1.100",
  "id.orig_p": 54321,
  "id.resp_h": "10.0.0.1",
  "id.resp_p": 443,
  "version": "TLSv13",
  "cipher": "TLS_AES_256_GCM_SHA384",
  "curve": "x25519",
  "server_name": "api.example.com",
  "resumed": false,
  "established": true,
  "cert_chain_fuids": ["FxxxxxAAAAA"],
  "client_cert_chain_fuids": []
}
```

### x509.log (standard Zeek JSON)
```json
{
  "ts": 1735000000.0,
  "id": "FxxxxxAAAAA",
  "certificate.version": 3,
  "certificate.serial": "01:23:45:67",
  "certificate.subject": "CN=api.example.com,O=Example Corp",
  "certificate.issuer": "CN=Example CA",
  "certificate.not_valid_before": 1700000000.0,
  "certificate.not_valid_after": 1830000000.0,
  "certificate.key_alg": "rsaEncryption",
  "certificate.sig_alg": "sha256WithRSAEncryption",
  "certificate.key_type": "rsa",
  "certificate.key_length": 2048,
  "certificate.exponent": "65537"
}
```

### ssh.log (standard Zeek JSON)
```json
{
  "ts": 1735000000.0,
  "uid": "CsshAB1234",
  "id.orig_h": "192.168.1.50",
  "id.orig_p": 55000,
  "id.resp_h": "10.0.0.5",
  "id.resp_p": 22,
  "version": 2,
  "auth_success": true,
  "auth_attempts": 1,
  "client": "OpenSSH_9.0",
  "server": "OpenSSH_8.9p1",
  "cipher_alg": "chacha20-poly1305@openssh.com",
  "mac_alg": "umac-64-etm@openssh.com",
  "compression_alg": "none",
  "kex_alg": "curve25519-sha256",
  "host_key_alg": "ssh-ed25519",
  "host_key": "AAAA..."
}
```

### cbom_crypto.log (custom CBOM log)
```json
{
  "ts": 1735000000.0,
  "uid": "CnAbbL1234abcd",
  "id.orig_h": "192.168.1.100",
  "id.orig_p": 54321,
  "id.resp_h": "10.0.0.1",
  "id.resp_p": 443,
  "protocol": "ssl",
  "algorithm": "ECDH",
  "key_size": 256,
  "crypto_type": "key_exchange",
  "quantum_class": "vulnerable",
  "pqc_replace": "ML-KEM-768",
  "evidence": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  "location": "api.example.com:443"
}
```

---

## Zeek Startup Command

```bash
# In docker-compose.yml (zeek service command):
zeek -i ${ZEEK_INTERFACE:-eth0} \
     -C \
     local \
     /zeek/scripts/crypto-detection.zeek

# Flags:
#   -i eth0   Listen on host interface (host network mode)
#   -C        Do not validate checksums (required for some environments)
#   local     Load local.zeek site policy
```

---

## Troubleshooting

```bash
# Check Zeek is capturing traffic
docker logs cbom-zeek --tail=50

# Verify logs are being written
ls -la /path/to/shared/zeek-logs/

# Check which interface Zeek is using
docker exec cbom-zeek zeek -i list

# Run Zeek manually with a specific interface
docker exec cbom-zeek zeek -i eth0 -C local /zeek/scripts/crypto-detection.zeek

# Test with a pcap file (offline analysis)
docker exec cbom-zeek zeek -r /tmp/capture.pcap local /zeek/scripts/crypto-detection.zeek

# Verify JSON output format
docker exec cbom-zeek cat /zeek/logs/ssl.log | python3 -m json.tool | head -30

# Check shared volume permissions
chmod 777 shared/zeek-logs/
```

---

## Performance Tuning

For high-throughput environments (> 1 Gbps):

```bash
# zeek/local.zeek additions for performance:

# Use multiple Zeek workers (requires PF_RING or AF_PACKET)
# Start with: zeekctl deploy (cluster mode)

# Disable unused analyzers to reduce CPU:
# @load-sigs    (only if using signature matching)

# Increase log buffer
redef Log::default_rotation_interval = 30min;  # More frequent rotation for large volumes

# Limit extracted file size
redef FileExtract::prefix = "/zeek/logs/extracted/";
redef FileExtract::default_limit = 10485760;   # 10 MB max per file
```
