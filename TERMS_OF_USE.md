# Terms of Use for Valkyrie

**Effective Date:** September 19, 2026  
**Last Updated:** September 19, 2026  

---

## 1. Acceptance of Terms

Welcome to **Valkyrie** ("Platform", "Service", "we", "us", or "our"). By registering for an account, accessing, or using the Valkyrie security scanning service, you acknowledge that you have read, understood, and agreed to be legally bound by these Terms of Use ("Terms").

These Terms constitute a legally valid and binding electronic agreement pursuant to the **Electronic Transactions Act, 2008 (Act 772)** of Ghana. If you do not agree with any part of these Terms, you must immediately discontinue use of the Service.

---

## 2. Description of the Service

Valkyrie is an automated, web-based security inspection tool designed for software developers, engineering teams, and organizations. The Service provides:
1. **Repository Intake & Dependency Parsing**: Ingestion of public GitHub repositories to extract dependency manifests (`package.json`, `.csproj`, `requirements.txt`).
2. **Vulnerability Analysis**: Cross-referencing identified third-party packages against open vulnerability databases (including OSV.dev).
3. **Static Code Pattern Scanning**: Regex-driven detection of potential security risks (such as hardcoded credentials, raw SQL injection patterns, exposed configurations, and unencrypted HTTP endpoints).
4. **AI-Assisted Remediation Explanations**: Plain-English risk descriptions and suggested code fixes generated via third-party artificial intelligence models.
5. **Dashboard Reporting**: Aggregated security grading (A–F) and historical scan records.

---

## 3. Eligibility, Account Registration & Security

### 3.1 Eligibility
You must be at least 18 years old or possess legal capacity to enter into binding agreements in your jurisdiction to create an account and use Valkyrie.

### 3.2 Account Credentials
* You agree to provide accurate registration details (username and password).
* You are solely responsible for maintaining the confidentiality of your credentials and for all activities that occur under your account.
* Valkyrie implements automated account lockout protection: accounts are locked for 5 minutes after 5 consecutive failed login attempts to guard against unauthorized access.
* You must immediately notify us if you suspect any unauthorized access to or compromise of your account.

---

## 4. Acceptable Use Policy & Scope Restrictions

To maintain platform stability, integrity, and compliance with the **Cybersecurity Act, 2020 (Act 1038)**, you agree to adhere strictly to the following usage rules:

### 4.1 Permitted Use
* You may only submit URLs for **public GitHub repositories** that you own, maintain, or have lawful authorization or license to inspect.
* You agree to use scan results, vulnerability indicators, and remediation suggestions exclusively for constructive, defensive security hardening and educational purposes.

### 4.2 Prohibited Activities
You agree **NOT** to:
1. **Scan Unauthorized or Hostile Targets**: Submit repository URLs with the intent to discover exploitable vulnerabilities for malicious exploitation, extortion, or unauthorized intrusion.
2. **Abuse Platform Rate Limits**: Bypass, circumvent, or attempt to disable the platform's inbound rate limiters (enforcing 10 scans/min and 15 auth requests/min) through proxies, automated scrapers, or botnets.
3. **Interfere with Service Infrastructure**: Engage in any denial-of-service (DoS/DDoS) activity, introduce ransomware, worms, or malicious scripts into our servers, or violate provisions of the Cybersecurity Act (Act 1038).
4. **Attempt Reverse Engineering**: Reverse-engineer, decompile, or disassemble the underlying Valkyrie platform code, proprietary scoring algorithms, or infrastructure controls.
5. **Misrepresent Identity**: Impersonate any individual, organization, or developer, or submit repositories under false pretenses.

---

## 5. Scope & Architectural Boundaries

Users acknowledge and agree that Valkyrie operates within strict, deliberate system boundaries:
* **Public Repositories Only**: Valkyrie does not access, scan, or store credentials for private repositories.
* **No Automatic Code Modification**: Valkyrie provides remediation suggestions in text and code snippets only. The Service will **never** commit changes, push code, or open pull requests on your repositories.
* **On-Demand Processing**: Valkyrie is an on-demand inspection tool. It does not perform continuous real-time monitoring, webhook listening, or automated recurring repository rescanning.
* **Supported Ecosystems**: Package vulnerability lookups are limited to **npm** and **NuGet**, with partial support for **Python** (static code pattern analysis only; no PyPI package vulnerability checks).

---

## 6. Intellectual Property Rights

### 6.1 Your Repositories & Code
You retain full ownership, copyright, and all intellectual property rights in and to your source code, repositories, and dependencies. Valkyrie claims no ownership or proprietary interest in any code submitted for scanning.

### 6.2 Valkyrie Platform Rights
All rights, title, and interest in the Valkyrie platform—including its source code, design system, UI components, branding, algorithms, and documentation—are protected under the **Copyright Act, 2005 (Act 690)** and applicable intellectual property laws.

---

## 7. AI Explanations & Security Disclaimer

### 7.1 Advisory Nature of AI Suggestions
Remediation suggestions and risk explanations are generated by artificial intelligence endpoints (including AgentRouter). AI-generated content is provided for informational and guidance purposes only. You must independently review, test, and validate any suggested code fixes before deploying them into production environments.

### 7.2 No Warranty of Absolute Security ("AS IS")
**VALKYRIE IS PROVIDED ON AN "AS IS" AND "AS AVAILABLE" BASIS WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED.** 

While Valkyrie strives for accuracy:
* We do not warrant that all vulnerabilities, security flaws, or bugs in your codebase will be detected.
* We do not warrant that code flagged as an issue is guaranteed to be exploitable (false positives may occur).
* Static regex scanning and open-source vulnerability databases (such as OSV.dev) are inherently bounded and cannot replace a comprehensive, manual penetration test or formal third-party security audit.

---

## 8. Limitation of Liability

To the maximum extent permitted by applicable law under the **Electronic Transactions Act, 2008 (Act 772)**:

* **No Consequential Damages**: In no event shall Valkyrie, its creators, developers, contributors, or service hosts be liable for any indirect, incidental, consequential, special, or punitive damages, including loss of profits, data corruption, system downtime, security breaches, or reputational harm arising out of or related to your use of or inability to use the Service.
* **Aggregate Liability Cap**: In all circumstances, Valkyrie's total cumulative liability arising from any claim related to the Service shall not exceed the amount paid by you (if any) to access the Service during the twelve (12) months preceding the claim, or GHS 100, whichever is lower.

---

## 9. Account Termination & Suspension

We reserve the right, at our sole discretion and without prior notice, to suspend, disable, or terminate user accounts or access to the Service if:
1. You breach any provision of these Terms or the Acceptable Use Policy.
2. Your activity poses a security threat to the platform, infrastructure, or other users.
3. Required to do so by lawful order of a competent regulatory authority or court of law in Ghana (including the Cyber Security Authority or Data Protection Commission).

---

## 10. Governing Law & Dispute Resolution

These Terms and any disputes arising out of or relating to your use of Valkyrie shall be governed by and construed in accordance with the laws of the **Republic of Ghana**, specifically including:
* **The Electronic Transactions Act, 2008 (Act 772)**
* **The Data Protection Act, 2012 (Act 843)**
* **The Cybersecurity Act, 2020 (Act 1038)**

Any dispute, controversy, or claim arising under or relating to these Terms shall be resolved amicably through good-faith mutual negotiation. If unresolved, disputes shall be submitted to the exclusive jurisdiction of the competent courts of Ghana.

---

## 11. Modifications to Terms

We reserve the right to revise or update these Terms at any time. Any changes will become effective immediately upon posting the updated Terms in the repository. Your continued use of the Service following the posting of revised Terms constitutes your acceptance of the amendments.

---

## 12. Contact & Notices

For any questions, legal notices, or feedback regarding these Terms of Use, please reach out via our official GitHub repository:  
👉 **GitHub:** [https://github.com/hendrix-llouchi/Valkyire](https://github.com/hendrix-llouchi/Valkyire)
