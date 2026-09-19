# Privacy Policy for Valkyrie

**Effective Date:** September 17, 2026  
**Last Updated:** September 17, 2026  

---

## 1. Introduction & Overview

Welcome to **Valkyrie** (we, our, or the Platform). Valkyrie is an automated, web-based security tool that inspects public GitHub repositories for known vulnerable dependencies and insecure code patterns, leveraging artificial intelligence to provide plain-English explanations and remediation suggestions.

We are committed to protecting your personal information and respecting your privacy rights. This Privacy Policy outlines the types of information we collect, how we handle, process, and safeguard that data, and your rights under applicable privacy legislation, specifically **Ghana's Data Protection Act, 2012 (Act 843)**, the **Electronic Transactions Act, 2008 (Act 772)**, and international privacy principles.

---

## 2. The Legal Basis for Processing Personal Data

Under **Section 17–24 of Act 843 (Ghana)** and standard global privacy frameworks, we collect and process personal data based on the following legal grounds:

1. **User Consent:** When you create an account, register on Valkyrie, or initiate repository scans.
2. **Contractual Necessity:** Processing required to provide you with scan reports, dashboard access, and authenticated sessions.
3. **Legitimate Interests:** Monitoring system security, applying rate limits to prevent brute-force attacks or denial of service, and improving scan accuracy.
4. **Legal Compliance:** Complying with statutory reporting obligations, court orders, or lawful regulatory inquiries from the **Data Protection Commission (DPC)** or the **Cyber Security Authority (CSA)**.

---

## 3. Information We Collect

### A. Information You Provide Directly
* **Account Information:** When you register for an account, we collect your **Username** and a cryptographic hash of your **Password**. We do not store plaintext passwords.
* **Scan Targets:** When you request a repository inspection, you provide a public GitHub repository URL (e.g., https://github.com/owner/repo).

### B. Information Automatically Collected During Use
* **Session & Authentication State:** Cryptographic session cookies powered by ASP.NET Core Data Protection to preserve your authenticated state across server restarts.
* **Network & Security Logs:** IP addresses (used exclusively for rate limiting to enforce 10 scans/min and 15 auth requests/min to protect against automated abuse), HTTP request headers, timestamps, and browser user-agent strings.
* **Telemetry & APM Diagnostics:** Performance metrics, unhandled exception traces, and endpoint response latencies collected via Azure Application Insights.

### C. Data We Deliberately DO NOT Collect
* **No Private Repositories:** Valkyrie only operates on public GitHub repositories. We do not request, store, or accept GitHub OAuth tokens, personal access tokens (PATs) belonging to users, or private SSH keys.
* **No Payment or Financial Data:** We do not collect credit card numbers, mobile money pins, or bank account credentials.
* **No Special Category (Sensitive) Data:** We do not collect biometric, health, political, religious, or philosophical information.

---

## 4. How We Use Your Information

We process the collected data strictly for the following operational purposes:
1. **Executing Security Scans:** Inspecting public dependency manifests (package.json, .csproj, equirements.txt) and code patterns.
2. **Generating Vulnerability Reports:** Cross-referencing detected packages against OSV.dev and generating AI explanations.
3. **Session Continuity & Dashboard Display:** Storing scan results (security grade, issue counts, repository name, timestamps) associated with your user account.
4. **Rate Limiting & Abuse Prevention:** Enforcing Layer 9 rate limits to preserve service stability and guard against denial of service.
5. **System Diagnostics:** Detecting system bugs, API timeouts, or unhandled exceptions using Application Insights.

---

## 5. Third-Party Services & Cross-Border Data Disclosures

To deliver our scanning and AI capabilities, Valkyrie interfaces with trusted external APIs. We ensure that data disclosures are strictly limited to what is necessary:

| Service / Sub-processor | Purpose | Data Transferred |
|---|---|---|
| **GitHub REST API (v3)** | Retrieving public repository file trees and manifests | Public repository URL and public file paths. |
| **OSV.dev (Open Source Vulnerabilities)** | Querying package CVE databases | Package names and version strings (no personal or user identifying data). |
| **AgentRouter / AI LLM Endpoint** | Generating plain-English vulnerability explanations and suggested code fixes | Vulnerability descriptions, issue types, and small sanitized code snippets. |
| **Microsoft Azure** | Application hosting, SQL database storage, and telemetry | Encrypted account records, scan history tables, and diagnostic traces. |

---

## 6. Data Storage, Security & Retention

### A. Security Safeguards (Principle 6, Act 843)
In accordance with **Section 28 of Act 843**, we implement robust technical and organizational security controls:
* **Encryption at Rest:** User password hashes and session keys are secured using industry-standard hashing (PBKDF2/Argon2) and EF Core Data Protection key storage.
* **Encryption in Transit:** All traffic between your browser, the Valkyrie server, and external endpoints is encrypted via **HTTPS (TLS 1.2 / TLS 1.3)**.
* **Rate Limiting Protection:** Inbound IP rate limiting guards against brute-force password guessing and volumetric scanning floods.

### B. Data Retention
* **User Accounts:** Maintained until you request account deletion.
* **Scan History:** Scan records and reports are stored in your user dashboard for reference until cleared by you or upon account removal.
* **Diagnostic Logs:** Application Insights telemetry traces are retained for a rolling period (30–90 days) before automatic purge.

---

## 7. Your Privacy Rights

Under the **Data Protection Act, 2012 (Act 843)**, users retain enforceable rights regarding their personal data:

* **Right to Access (Section 35):** You have the right to request a copy of the personal information Valkyrie holds about you.
* **Right to Rectification (Section 36):** You may request correction or updating of inaccurate account credentials.
* **Right to Erasure / Deletion (Section 37):** You have the right to request the deletion of your user account and associated scan history.
* **Right to Object to Processing (Section 38):** You may object to data processing where such processing causes unwarranted distress or does not conform to agreed statutory purposes.
* **Right to Data Portability:** You may request your scan report data in a machine-readable format.

To exercise any of these rights, you can reach out via the repository issue tracker or our designated support channel.

---

## 8. Cookies & Local Tracking

Valkyrie uses strictly necessary, functional cookies:
* **.AspNetCore.Identity.Application**: A secure session cookie used to maintain authenticated user login sessions.
* **Cookie Characteristics:** Set with HttpOnly = true, Secure = true (over HTTPS), and SameSite = Lax to protect against cross-site scripting (XSS) and cross-site request forgery (CSRF).
* We do **not** use advertising, marketing, or cross-site tracking cookies.

---

## 9. Regulatory Authority & Complaints

If you believe your personal data has been handled in violation of Ghanaian data protection laws, you have the right to lodge a formal complaint with the statutory supervisory authority:

**Data Protection Commission (DPC) Ghana**  
* Website: [https://www.dataprotection.org.gh](https://www.dataprotection.org.gh)  
* Legal Framework: Data Protection Act, 2012 (Act 843)

---

## 10. Updates to This Privacy Policy

We may update this Privacy Policy periodically to reflect new platform capabilities, architectural improvements, or regulatory updates. Any material modifications will be noted in our repository changelog and accompanied by an updated Last Updated timestamp at the top of this document.

---

## 11. Contact & Questions

For any questions, feedback, or requests regarding this Privacy Policy or Valkyrie's data practices, please open an issue on the official GitHub repository:  
👉 **GitHub:** [https://github.com/hendrix-llouchi/Valkyire](https://github.com/hendrix-llouchi/Valkyire)
