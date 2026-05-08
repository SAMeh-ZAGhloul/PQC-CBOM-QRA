# BRD: Quantum-Safe CBOM Discovery Platform

> **Version:** 1.0 | **Status:** Draft | **Classification:** Confidential | **Date:** June 2025
> **Approvers:** CISO · CEO · Product Owner

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [User Roles & Stakeholders](#2-user-roles--stakeholders)
3. [Functional Requirements](#3-functional-requirements)
   - 3.1 [Discovery Engine](#31-discovery-engine)
   - 3.2 [CBOM Generation & Management](#32-cbom-generation--management)
   - 3.3 [Risk Scoring — QARS](#33-risk-scoring--qars)
   - 3.4 [Readiness Scoring — QSRI](#34-readiness-scoring--qsri)
   - 3.5 [Dashboard & Reporting](#35-dashboard--reporting)
4. [Non-Functional Requirements](#4-non-functional-requirements)
5. [User Stories](#5-user-stories)
6. [Constraints, Assumptions & Open Items](#6-constraints-assumptions--open-items)
7. [Glossary](#7-glossary)

---

## 1. Executive Summary

### 1.1 Vision

The **Quantum-Safe CBOM Discovery Platform** is a commercial enterprise product that enables organizations to discover, inventory, score, and remediate their entire cryptographic attack surface in preparation for the post-quantum cryptography (PQC) transition mandated by NIST, DORA, NIS2, and NSM-10.

The platform combines:
- Automated network-level discovery (Zeek)
- Static code analysis (AST)
- AI-assisted file classification (Magika)
- LLM-powered semantic analysis (fallback tier)
- Data-at-rest encryption discovery (databases)
- Certificate and TLS endpoint inspection

All findings are unified into a **CycloneDX 1.6 CBOM**. Each asset is scored via **QARS** (Quantum-Adjusted Risk Score) and organizational migration capability is measured by **QSRI** (Quantum Security Readiness Index).

### 1.2 Business Goals

| # | Goal | Driver |
|---|------|--------|
| 1 | Regulatory compliance | DORA, NIS2, NSM-10 — auditable CBOM outputs |
| 2 | Risk quantification | Per-asset QARS + organizational QSRI for defensible migration roadmap |
| 3 | PQC migration acceleration | Automated remediation aligned to NIST FIPS 203/204/205 |

### 1.3 12-Month Success Criteria

| Metric | Target |
|--------|--------|
| CBOM asset coverage | >= 90% of known crypto assets |
| QARS score | < 0.6 across all critical assets |
| PQC migration roadmap | Completed and PoC initiated |
| Regulatory audit | First audit passed |
| Enterprise clients | First client onboarded and live |

---

## 2. User Roles & Stakeholders

### 2.1 Primary Users

#### Security Engineer
- **Profile:** Deep cryptography, PKI, TLS, SSH expertise. Daily platform user.
- **Responsibilities:**
  - Run and schedule CBOM discovery scans across all surfaces
  - Review findings, validate classifications, manage false positives
  - Execute remediation: certificate rotation, library migration, key management
  - Integrate platform into CI/CD pipelines for PQC gating

#### CISO
- **Profile:** Security strategy background. Weekly dashboard user. Joint owner of remediation decisions with CEO.
- **Responsibilities:**
  - Review QARS and QSRI scores to track migration progress
  - Approve remediation priorities and resource allocation
  - Sign off on audit evidence packages
  - Present PQC migration roadmap to executive leadership

#### Auditor / Compliance Officer
- **Profile:** Compliance-focused, non-technical. Quarterly report reader.
- **Responsibilities:**
  - Read-only access to CBOM inventory and findings
  - Download compliance evidence packages (DORA, NIS2, NSM-10)
  - Track remediation progress against regulatory deadlines

### 2.2 Secondary / External Stakeholders

| Role | Access Level | Notes |
|------|-------------|-------|
| CEO / Board | Executive KPI dashboard | Business risk framing, no technical detail |
| External Regulator | Exported CBOM + compliance packages | No direct platform access |
| Third-Party Auditor | Time-limited read-only portal | Specific CBOM snapshot only |
| Supply Chain / Vendor | CBOM export excerpts | Out of scope for v1.0 |

---

## 3. Functional Requirements

> **Priority Legend:**
> - `MUST` — Required for MVP / v1.0
> - `SHOULD` — High value, target v1.1
> - `NICE` — Future / Phase 2

---

### 3.1 Discovery Engine

| ID | Requirement | Priority | Notes |
|----|-------------|----------|-------|
| FR-D01 | Passive network capture via Zeek: detect SSL/TLS cipher suites, X.509 certificates, SSH key algorithms, and file hashes from live traffic | `MUST` | Zeek 6.x |
| FR-D02 | AST-based static code analysis for Python, Java, Go, JavaScript/TypeScript, C/C++ — detect crypto API calls, imports, algorithm parameters | `MUST` | Tree-sitter based |
| FR-D03 | AI-powered file-type classification (Magika) to route files to correct scanner before analysis | `MUST` | 5 ms/file, 200+ types |
| FR-D04 | LLM-assisted semantic analysis for homegrown crypto, indirect/wrapped calls, IaC configs, comment-revealed algorithm intent | `MUST` | Targeted fallback only |
| FR-D05 | Certificate and TLS endpoint inspection: parse PEM, DER, PKCS#12, JKS; probe live HTTPS endpoints | `MUST` | FIPS cert parsing |
| FR-D06 | Data-at-rest encryption discovery: detect AES, 3DES, RC4 in PostgreSQL, MySQL, MongoDB, Oracle, SQL Server (TDE + field-level) | `MUST` | DB TDE + field-level |
| FR-D07 | Binary and bytecode analysis: scan ELF, PE, Mach-O, JVM .class, .pyc for crypto symbol tables | `MUST` | nm/objdump based |
| FR-D08 | Container and archive unpacking: recurse ZIP, JAR, WAR, Docker layers for nested crypto assets | `MUST` | Max 5 depth levels |
| FR-D09 | IaC scanning: Terraform, Helm, CloudFormation, Ansible for TLS policy and cipher suite references | `SHOULD` | AWS/GCP/Azure |
| FR-D10 | Dependency manifest scanning: requirements.txt, pom.xml, go.mod, package.json for crypto libraries and versions | `SHOULD` | CVE linkage |
| FR-D11 | HSM inventory discovery via PKCS#11 interface query | `NICE` | Phase 2 |

---

### 3.2 CBOM Generation & Management

| ID | Requirement | Priority | Notes |
|----|-------------|----------|-------|
| FR-C01 | Generate CycloneDX 1.6-compliant CBOM JSON/XML for every asset: algorithm, key size, location, usage context, quantum vulnerability | `MUST` | OWASP standard |
| FR-C02 | Deduplicate crypto assets across discovery sources, merging network and code evidence for the same asset | `MUST` | UUID-based dedup |
| FR-C03 | Classify every algorithm: quantum-vulnerable (RSA, ECC, DH) / partially safe (AES-128, SHA-256) / quantum-safe (AES-256, SHA-3) / PQC (ML-KEM, ML-DSA, SLH-DSA) | `MUST` | NIST categories |
| FR-C04 | Assign PQC replacement recommendation per vulnerable asset — aligned to FIPS 203, 204, 205 | `MUST` | NIST approved only |
| FR-C05 | Asset lineage tracking: first discovered, last seen, remediation applied | `MUST` | Audit trail |
| FR-C06 | CBOM versioning: each scan produces a new version with delta highlighting vs previous | `SHOULD` | Diff export |
| FR-C07 | Asset annotation: owner, system name, data classification, migration status | `SHOULD` | Manual enrichment |
| FR-C08 | SBOM-to-CBOM bridge: ingest CycloneDX or SPDX SBOMs and extract crypto component data | `NICE` | Phase 2 |

---

### 3.3 Risk Scoring — QARS

> **Mosca Inequality:** If `X (data shelf life) + Y (migration time) >= Z (years to Q-Day)` then action is urgent.
> QARS score range: **0.0 (safe) to 1.0 (critical)**

| ID | Requirement | Priority | Notes |
|----|-------------|----------|-------|
| FR-Q01 | Calculate QARS per asset using shelf-life (X), migration timeline (Y), quantum threat horizon (Z). Flag when X + Y >= Z | `MUST` | Mosca inequality |
| FR-Q02 | Apply sector-specific risk profiles: Financial (DORA), Healthcare (GDPR+NIS2), Government (NSM-10), Critical Infrastructure | `MUST` | Per-sector weights |
| FR-Q03 | Data sensitivity weighting: public / internal / confidential / restricted amplifies base QARS | `MUST` | 4 sensitivity levels |
| FR-Q04 | Exposure factor: internet-facing assets scored higher than internal-only | `MUST` | Network exposure |
| FR-Q05 | Prioritized remediation queue sorted by QARS descending with NIST PQC replacement per asset | `MUST` | Actionable output |
| FR-Q06 | Map findings to DORA, NIS2, NSM-10 control requirements for compliance gap reporting | `MUST` | Regulatory mapping |
| FR-Q07 | Configurable Q-Day year: default 2030, adjustable to 2033 | `SHOULD` | Scenario planning |
| FR-Q08 | QARS trend over time: score improvement as remediation is applied | `SHOULD` | Progress tracking |

---

### 3.4 Readiness Scoring — QSRI

> **QSRI score range: 0-100** across 8 weighted dimensions at maturity levels 0-5.

| Dimension | Weight |
|-----------|--------|
| Cryptographic Inventory & Discovery | 15% |
| Risk Assessment | 15% |
| Crypto Agility | 15% |
| Migration Planning | 15% |
| Technical Implementation | 10% |
| Supply Chain Security | 10% |
| Governance & Compliance | 10% |
| Awareness & Training | 10% |

| ID | Requirement | Priority | Notes |
|----|-------------|----------|-------|
| FR-R01 | Calculate QSRI score across all 8 dimensions using weighted maturity formula | `MUST` | Weighted formula |
| FR-R02 | Score each dimension on 0-5 maturity scale with defined assessment criteria per level | `MUST` | Maturity model |
| FR-R03 | QSRI radar chart visualization for CISO and executive reporting | `MUST` | Dashboard widget |
| FR-R04 | Dimension-level improvement recommendations with effort and impact estimates | `MUST` | Remediation guidance |
| FR-R05 | Auto-populate QSRI Inventory dimension score from CBOM coverage percentage | `MUST` | CBOM integration |
| FR-R06 | Benchmark QSRI scores against anonymized sector peer averages | `SHOULD` | Phase 2 data |
| FR-R07 | Generate QSRI improvement roadmap as a phased 12-month plan with milestones | `SHOULD` | Roadmap output |

---

### 3.5 Dashboard & Reporting

| ID | Requirement | Priority | Notes |
|----|-------------|----------|-------|
| FR-P01 | Unified web dashboard: CBOM inventory, QARS scores, QSRI index, findings, certificates, migration progress | `MUST` | Role-based views |
| FR-P02 | Role-based views: Engineer (full technical), CISO (risk/compliance), Auditor (read-only), CEO (executive KPI) | `MUST` | RBAC gated |
| FR-P03 | Export CBOM as CycloneDX JSON/XML, CSV, and PDF audit report | `MUST` | Audit evidence |
| FR-P04 | Compliance evidence packages for DORA, NIS2, NSM-10 with control mapping | `MUST` | Regulator-ready |
| FR-P05 | Real-time scan progress and CBOM auto-refresh on new log detection | `MUST` | Queue-based |
| FR-P06 | Findings workflow: assign owner, set due date, track status (open / in-progress / resolved / accepted-risk) | `MUST` | Workflow states |
| FR-P07 | Certificate expiry alerts: notify at 90, 30, and 7 days via email and webhook | `MUST` | Email/webhook |
| FR-P08 | Executive KPI dashboard: PQC readiness score, assets at risk, days to Q-Day, compliance status | `SHOULD` | CEO/Board view |
| FR-P09 | PQC migration roadmap view: phased timeline from discovery to PoC to full migration with effort estimates | `SHOULD` | Gantt-style |
| FR-P10 | Scheduled reports: weekly QARS digest, monthly QSRI progress, quarterly compliance package | `SHOULD` | Email delivery |
| FR-P11 | White-label branding for reseller/MSSP clients | `NICE` | Phase 2 |

---

## 4. Non-Functional Requirements

### 4.1 Security

| ID | Requirement | Priority | Notes |
|----|-------------|----------|-------|
| NFR-S01 | All data in transit encrypted with TLS 1.3. No cleartext transmission | `MUST` | Zero cleartext |
| NFR-S02 | All data at rest encrypted with AES-256-GCM via HSM or enterprise KMS (AWS KMS, Azure Key Vault, HashiCorp Vault) | `MUST` | FIPS 140-2 L2+ |
| NFR-S03 | RBAC with least-privilege enforcement. 5 roles: admin, engineer, CISO, auditor, external-auditor | `MUST` | 5 roles minimum |
| NFR-S04 | MFA mandatory for all accounts. SAML 2.0 / OIDC SSO for enterprise clients | `MUST` | SSO required |
| NFR-S05 | Tamper-evident audit log of all user actions, API calls, scans, exports. Retained 7 years | `MUST` | Regulatory retention |
| NFR-S06 | Annual third-party penetration test. Critical/high findings remediated within 30 days | `MUST` | SOC 2 Type II |
| NFR-S07 | No crypto asset data leaves client tenancy boundary. Multi-tenant isolation at infrastructure level | `MUST` | Data residency |
| NFR-S08 | Vulnerability disclosure program and CVE tracking for platform components | `SHOULD` | Responsible disclosure |

### 4.2 Scalability & Performance

| ID | Requirement | Priority | Target |
|----|-------------|----------|--------|
| NFR-P01 | Full scan of 10,000 source files in under 4 hours | `MUST` | Parallelized workers |
| NFR-P02 | Magika file-type classification >= 500 files/second per node | `MUST` | 5 ms/file |
| NFR-P03 | CBOM generation + QARS scoring for 50,000 assets in under 10 minutes | `MUST` | Batch processing |
| NFR-P04 | Dashboard API p95 response under 500ms at 100 concurrent users | `MUST` | SLA target |
| NFR-P05 | Horizontal scaling of discovery workers, analyzer, dashboard via Kubernetes | `MUST` | K8s Helm chart |
| NFR-P06 | Support 100 simultaneous enterprise tenant scans | `MUST` | Multi-tenant SaaS |
| NFR-P07 | CBOM database: 10M assets/tenant with sub-second query | `SHOULD` | PostgreSQL + index |
| NFR-P08 | Zeek network capture: up to 10 Gbps on single sensor node | `SHOULD` | High-throughput |

### 4.3 Availability & Reliability

| ID | Requirement | Priority | Notes |
|----|-------------|----------|-------|
| NFR-A01 | Platform SLA: 99.9% uptime for dashboard and API | `MUST` | 3 nines |
| NFR-A02 | RTO: 4 hours. RPO: 1 hour | `MUST` | DR requirement |
| NFR-A03 | Zeek sensors operate independently with local 24-hour buffer on connectivity loss | `MUST` | Edge resilience |
| NFR-A04 | Automated daily CBOM backups encrypted at rest and replicated to secondary region | `MUST` | Backup policy |

### 4.4 Compliance & Standards

| ID | Requirement | Priority | Standard |
|----|-------------|----------|---------|
| NFR-C01 | CycloneDX 1.6 compliance for all CBOM outputs | `MUST` | OWASP |
| NFR-C02 | NIST SP 800-208 and FIPS 203/204/205 alignment for all PQC recommendations | `MUST` | NIST PQC |
| NFR-C03 | GDPR Article 32 compliance for EU client data | `MUST` | EU data residency |
| NFR-C04 | SOC 2 Type II certification within 18 months of launch | `MUST` | Enterprise sales |
| NFR-C05 | ISO 27001 certification roadmap initiated at launch | `SHOULD` | Enterprise sales |

### 4.5 Usability

| ID | Requirement | Priority | Notes |
|----|-------------|----------|-------|
| NFR-U01 | Security engineer can run full scan with 30-minute onboarding or less | `MUST` | Time-to-value |
| NFR-U02 | CISO dashboard uses business risk language — no cryptographic jargon | `MUST` | Non-technical view |
| NFR-U03 | WCAG 2.1 AA accessibility compliance | `SHOULD` | Accessibility |
| NFR-U04 | English for v1.0. French and German localization in Phase 2 | `NICE` | EU market |

---

## 5. User Stories

### 5.1 Security Engineer

| ID | User Story | Priority | Linked FR |
|----|-----------|----------|-----------|
| US-E01 | As a **Security Engineer**, I want to run a full discovery scan across all surfaces (network, code, certs, databases) so that I have a complete CBOM in a single workflow. | `MUST` | FR-D01 to D11 |
| US-E02 | As a **Security Engineer**, I want Magika to automatically route each file to the correct scanner so that I avoid parser errors and wasted scan time. | `MUST` | FR-D03 |
| US-E03 | As a **Security Engineer**, I want the LLM fallback to flag homegrown crypto in source files so that I catch custom implementations that rule-based scanners miss. | `MUST` | FR-D04 |
| US-E04 | As a **Security Engineer**, I want to see each asset's QARS score and Mosca inequality breakdown so that I can explain remediation urgency to stakeholders quantitatively. | `MUST` | FR-Q01 to Q05 |
| US-E05 | As a **Security Engineer**, I want to export the full CBOM as CycloneDX JSON so that I can feed it into downstream tooling and audit systems. | `MUST` | FR-C01, FR-P03 |
| US-E06 | As a **Security Engineer**, I want the scanner to detect database-level encryption (TDE, field-level AES) so that data-at-rest risks are included in the CBOM. | `MUST` | FR-D06 |
| US-E07 | As a **Security Engineer**, I want to configure a CI/CD integration so that any newly introduced quantum-vulnerable algorithm fails the pipeline gate. | `SHOULD` | FR-D02 |
| US-E08 | As a **Security Engineer**, I want delta comparison between CBOM versions so that I can see exactly what changed after each scan or remediation action. | `SHOULD` | FR-C06 |

### 5.2 CISO

| ID | User Story | Priority | Linked FR |
|----|-----------|----------|-----------|
| US-C01 | As a **CISO**, I want a single QSRI score with dimension breakdown so that I can report our quantum readiness posture to the board in one number. | `MUST` | FR-R01 to R05 |
| US-C02 | As a **CISO**, I want a prioritized remediation queue sorted by QARS so that I can allocate engineering resources to the highest-risk assets first. | `MUST` | FR-Q05 |
| US-C03 | As a **CISO**, I want compliance gap reports for DORA, NIS2, and NSM-10 automatically generated from the CBOM so that I do not need to manually map findings to controls. | `MUST` | FR-Q06, FR-P04 |
| US-C04 | As a **CISO**, I want to approve or defer remediation items with documented rationale so that there is an auditable decision trail. | `MUST` | FR-P06 |
| US-C05 | As a **CISO**, I want a PQC migration roadmap generated from CBOM and QSRI data so that I can present a phased 12-month plan to the CEO. | `SHOULD` | FR-R07, FR-P09 |
| US-C06 | As a **CISO**, I want weekly QARS digest emails so that I can monitor risk trends without logging into the dashboard. | `SHOULD` | FR-P10 |
| US-C07 | As a **CISO**, I want to benchmark our QSRI score against sector peers so that I can contextualize our maturity for the board. | `NICE` | FR-R06 |

### 5.3 Auditor / Compliance Officer

| ID | User Story | Priority | Linked FR |
|----|-----------|----------|-----------|
| US-A01 | As an **Auditor**, I want read-only access to the CBOM inventory and findings so that I can verify scope without modifying any data. | `MUST` | NFR-S03 |
| US-A02 | As an **Auditor**, I want to download a pre-formatted NIS2 compliance evidence package so that I can submit it directly to the regulatory body. | `MUST` | FR-P04 |
| US-A03 | As an **Auditor**, I want the full audit log of remediation actions and scan executions so that I can verify CBOM history integrity. | `MUST` | NFR-S05 |
| US-A04 | As an **Auditor**, I want certificate inventory with expiry dates and algorithm details so that I can verify no expired or weak certificates are in production. | `MUST` | FR-D05, FR-P07 |
| US-A05 | As an **External Auditor**, I want time-limited secure access to a specific CBOM snapshot so that I can perform my review without a permanent account. | `SHOULD` | NFR-S03 |

### 5.4 CEO / Executive

| ID | User Story | Priority | Linked FR |
|----|-----------|----------|-----------|
| US-X01 | As a **CEO**, I want an executive KPI dashboard showing PQC readiness score, critical assets at risk, and compliance status so that I can assess business risk without technical detail. | `SHOULD` | FR-P08 |
| US-X02 | As a **CEO**, I want to see days remaining to Q-Day alongside migration progress so that I understand urgency and whether we are on track. | `SHOULD` | FR-P08 |
| US-X03 | As a **CEO**, I want the QSRI improvement roadmap with investment requirements so that I can make informed resource allocation decisions. | `SHOULD` | FR-R07 |

---

## 6. Constraints, Assumptions & Open Items

### 6.1 Constraints

- **Timeline:** First enterprise client onboarding and first audit pass within 12 months.
- **Regulatory deadline:** NIS2 active now; DORA effective January 2025. MVP must produce NIS2/DORA evidence packages.
- **Greenfield inventory:** No existing CBOM. All discovery starts from zero.
- **Discovery surface:** Data-at-rest encryption (databases) required in v1.0 — not Phase 2.
- **Deployment model:** SaaS multi-tenant only for v1.0. No on-premise deployment.
- **Integrations:** Standalone dashboard and export only. No Jira/ServiceNow/SIEM in v1.0.

### 6.2 Assumptions

- Enterprise clients will provide network access for Zeek sensor deployment or allow agentless TLS inspection via span port or network tap.
- Source code repositories are accessible via API (GitHub, GitLab, Bitbucket) for AST scanning.
- Database credentials with read-only access will be provided for data-at-rest discovery.
- Q-Day is assumed to be **2030** as the default threat horizon for QARS calculations (adjustable per client).
- Clients are responsible for LLM API access if enabling the AI-assisted fallback analysis tier.

### 6.3 Open Items

| ID | Item | Owner | Due |
|----|------|-------|-----|
| OI-01 | Confirm Q-Day year (2030 vs 2033) with advisory board | CISO | Month 1 |
| OI-02 | Define data residency regions for EU and US tenants (GDPR) | Legal / CTO | Month 1 |
| OI-03 | Confirm supported database engines for data-at-rest discovery in v1.0 | Product Owner | Month 2 |
| OI-04 | Agree on LLM provider and API cost model for fallback analysis tier | CTO | Month 2 |
| OI-05 | Define external auditor portal access control model and audit trail scope | Security Lead | Month 3 |

---

## 7. Glossary

| Term | Definition |
|------|-----------|
| **AST** | Abstract Syntax Tree. Tree representation of source code used for static analysis of cryptographic API calls. |
| **CBOM** | Cryptographic Bill of Materials. Inventory of all cryptographic assets following CycloneDX 1.6 standard. |
| **CycloneDX** | OWASP open standard for SBOM and CBOM. Version 1.6 includes native `cryptoProperties` support. |
| **DORA** | Digital Operational Resilience Act. EU regulation effective January 2025 for financial entities. |
| **FIPS 203/204/205** | NIST standards for ML-KEM (key encapsulation), ML-DSA (digital signatures), SLH-DSA (hash-based signatures). |
| **LLM** | Large Language Model. Used in fallback tier to detect homegrown crypto and indirect algorithm usage. |
| **Magika** | Google AI-powered file-type classifier. Approximately 99% accuracy, 5 ms/file, 200+ content types. |
| **ML-DSA** | Module-Lattice Digital Signature Algorithm. NIST FIPS 204. PQC replacement for ECDSA and RSA signatures. |
| **ML-KEM** | Module-Lattice Key Encapsulation Mechanism. NIST FIPS 203. PQC replacement for ECDH and RSA key exchange. |
| **Mosca Inequality** | If X (data shelf life) + Y (migration time) >= Z (years to Q-Day) then action is urgent. Core of QARS. |
| **NIS2** | EU Network and Information Security Directive 2. Mandates crypto risk management for critical infrastructure. |
| **NSM-10** | US National Security Memorandum 10. Mandates federal agencies to inventory and migrate quantum-vulnerable crypto. |
| **PQC** | Post-Quantum Cryptography. Algorithms designed to resist attacks from cryptographically relevant quantum computers. |
| **Q-Day** | Estimated date when a quantum computer capable of breaking RSA/ECC becomes available. Default assumption: 2030. |
| **QARS** | Quantum-Adjusted Risk Score. Per-asset risk score 0.0 to 1.0 using Mosca inequality, sensitivity, and exposure. |
| **QSRI** | Quantum Security Readiness Index. Organizational maturity score 0-100 across 8 weighted dimensions. |
| **RBAC** | Role-Based Access Control. Permissions assigned based on user role. |
| **Shor's Algorithm** | Quantum algorithm breaking RSA, ECC, and DH in polynomial time on a sufficiently powerful quantum computer. |
| **SLH-DSA** | Stateless Hash-Based Digital Signature Algorithm. NIST FIPS 205. Conservative PQC signature scheme. |
| **TDE** | Transparent Data Encryption. Database encryption at rest in SQL Server, Oracle, PostgreSQL, MySQL. |
| **Zeek** | Open-source network analysis framework for passive capture and crypto detection of SSL/TLS, SSH, X.509 traffic. |

---

*End of document — BRD v1.0 | Quantum-Safe CBOM Discovery Platform | Confidential*
