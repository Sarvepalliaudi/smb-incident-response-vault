<!--
smb-ir-vault — Small Business 6-Phase Incident Response Plan & SHA3-512 Forensic Evidence Locker
Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan.
This specification and dual hardware-software architecture is original work created solely for this application.
Software Architect: Sarvepalli Audi Siva Bhanuvardhan
University: B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester),
Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India
Internship: Cybersecurity Virtual Internship — Dev/Craft by Fennark
https://devcraft.fennark.xyz | Intern ID: DEV-CRAFT-BQ2VPH | Task 7: Incident Response Plan
LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/
GitHub: https://github.com/Sarvepalliaudi
-->

# Small Business Incident Response Plan

> **Use and approval:** This operational template is for Kaveri Precision Components Pvt. Ltd. (KPC). The business owner must approve named contacts, authority, legal obligations, insurer requirements, retention, and recovery priorities before adoption. Keep a printed copy and a protected offline copy. Do not treat this example as legal advice.

## Executive scope

This plan is designed for a 35-employee regional B2B manufacturing and e-commerce supplier. In scope: Windows employee endpoints, on-premises identity and network services, a cloud ERP/accounting server, Microsoft 365 email and identity, VPN/RDP remote access, office and production networks, backups, and the customer order portal. It covers suspected or confirmed compromise, data exposure, fraud, service disruption, malware, and physical loss of business devices.

The objectives are to protect people and safety-critical manufacturing, limit business and customer impact, preserve evidence, communicate accurately, restore trusted services, and capture lessons. Safety and continuity decisions remain with the business owner and site lead. For an active incident, call emergency services if people or physical safety are at risk; do not delay containment to complete paperwork.

**Operating assumptions:** the business owner is incident commander (IC) until a named alternate takes over; an external managed security provider (MSP/MSSP) is on call; contact details are stored in the offline contact sheet; and the portal/ERP provider and cyber insurer have separate escalation channels. Replace role labels below with current names, phone numbers, and after-hours contacts. Never put personal contact details in a public repository.

## Incident response team and escalation

| Role | Primary responsibility | Small-business alternate / escalation |
|---|---|---|
| Incident Commander (IC), business owner | Declares severity; approves business decisions, external statements, and recovery | Operations director; if neither reachable, site lead may isolate a host and call the MSSP |
| Technical lead, IT/MSP | Triage, containment, evidence handling, recovery coordination | Named MSP on-call engineer; use the offline contract escalation number |
| Microsoft 365 / identity administrator | Revoke sessions, secure accounts, preserve audit data | MSP identity specialist |
| Site / production lead | People safety, production isolation, continuity and manual workarounds | Shift supervisor |
| Finance lead | Payment and invoice verification, bank escalation, fraud hold | Business owner |
| Privacy / legal contact | Breach assessment, preservation duties, regulator/customer notification advice | External counsel listed on offline contact sheet |
| Cyber-insurance / breach coach | Policy notice, approved responders, claim conditions | Insurer hotline listed in policy binder; notify promptly under policy terms |
| Communications lead | Approved employee/customer/vendor updates and incident log | IC |

### Contact escalation and service targets

Use the offline call tree. Acknowledge and start triage within the target; targets are internal response goals, not a guarantee of resolution.

| Severity | Example | Acknowledge / mobilize | Notify |
|---|---|---:|---|
| **P1 Critical** | Active ransomware; confirmed privileged account takeover; material customer/payment data exposure; production-wide outage | **15 minutes**, 24×7 | IC, IT/MSP, identity admin, site lead immediately; insurer/legal as soon as policy/counsel requires |
| **P2 High** | Confirmed malware or unauthorized access contained to one system; suspicious privileged login with no confirmed spread | 1 hour, including after hours | IC, IT/MSP, system owner; finance/legal if data or payment risk |
| **P3 Moderate** | Credible phishing click, isolated endpoint alert, suspicious sign-in blocked, no evidence of persistence | 4 business hours | IT/MSP and affected manager; elevate on new evidence |
| **P4 Low** | Unsuccessful spam/phishing attempt, policy alert with no interaction or compromise | 1 business day | IT queue; aggregate for trends |

**Escalate immediately** if scope expands, a second account/host is affected, encryption begins, sensitive data is plausibly accessed, attacker persistence is found, or a deadline to notify may apply. Any responder may call the IC and isolate a clearly compromised endpoint under the pre-approved authority below.

## Severity classification and incident record

Create one incident ID, UTC timeline, decision log, and evidence register. Record who made each decision, source and time zone of each log, confidence, affected assets/accounts, business impact, and next review time. Do not write passwords, access tokens, or unnecessary personal data in the incident record.

| Severity | Classification guide |
|---|---|
| P1 | Active threat or credible major impact to safety, production, privileged identity, regulated/sensitive data, payment integrity, or multiple systems |
| P2 | Confirmed compromise or material disruption, limited scope and no current evidence of broad spread |
| P3 | Credible event requiring investigation; compromise not established or limited to one user/device |
| P4 | Low-confidence or blocked event with no evidence of interaction or impact |

Severity is provisional. Record the evidence behind the decision and reassess after each material discovery. Uncertainty about data access is not proof that no access occurred.

## Phase 1 — Preparation

### Readiness checklist

- [ ] Maintain encrypted backups using **3-2-1**: three copies, two media/types, one offline or immutable copy. Keep backup administration separate from domain credentials. Test restoration quarterly and record the result.
- [ ] Enforce MFA for Microsoft 365, VPN, privileged accounts, and remote administration; prefer phishing-resistant methods for administrators. Disable legacy authentication where supported. Maintain two monitored emergency accounts with offline recovery procedures.
- [ ] Forward endpoint, firewall, VPN, identity, Microsoft 365, ERP, and portal logs to a centralized syslog/Wazuh monitoring service. Synchronize clocks to trusted time sources; retain logs according to legal, business, and insurer requirements.
- [ ] Keep an updated asset, data-flow, privileged-account, vendor, and service-owner inventory. Document which systems contain customer, employee, payment, and manufacturing data.
- [ ] Prepare a sealed, labeled forensic jump bag: write-protected/forensic USB media where available, clean laptop, network cables, camera, evidence labels, paper forms, spare storage, and this playbook. Verify tools and hashes before use; do not install unknown utilities on suspect hosts.
- [ ] Keep offline copies of the call tree, network diagram, backup restore procedure, insurance policy, counsel/privacy contacts, cloud provider escalation, and account-recovery instructions.
- [ ] Confirm legal counsel, cyber-insurance hotline/breach coach, bank fraud team, domain registrar, ISP, MSSP, Microsoft 365, ERP, and portal contacts. Confirm policy notice and approved-forensics requirements before an event.
- [ ] Rehearse phishing, ransomware, lost-device, and business-email-compromise scenarios at least annually. Test out-of-band communications if email is unavailable.
- [ ] Pre-approve the IC, IT/MSP on-call, or site lead to disconnect a clearly affected endpoint from network access and request emergency account/session revocation. Do not authorize destructive wiping or shutdown as a default response.

### Authority boundaries

The responder who detects credible active compromise may isolate the affected endpoint/network port immediately, preserve visible context, and notify the IC. The IC/IT lead may revoke a compromised session, block a confirmed malicious destination, and place a system into a clean VLAN. Broader shutdowns, production interruptions, public statements, ransom/payment decisions, evidence destruction, and restoration from backup require IC and relevant business/legal approval. Contact the insurer/counsel before engaging unapproved vendors where policy requires it.

## Phase 2 — Detection and Analysis

1. **Open an incident record.** Assign an ID, record discovery time in UTC and local time zone, reporter, source, systems, and a factual first description. Preserve original alerts and message headers.
2. **Triage phishing:** do not forward as an attachment through ordinary email. Preserve the message as an approved `.eml`/`.msg` export, complete headers, delivery/audit data, URL/domain, attachment hash, recipients, and whether anyone clicked, entered credentials, approved MFA, or paid an invoice.
3. **Review sign-in and remote access:** investigate anomalous after-hours VPN/RDP activity, unfamiliar geography/device, impossible travel, MFA fatigue, new forwarding rules, OAuth grants, privileged role changes, and sign-ins followed by mailbox searches or downloads. Compare with named employee schedules and known travel before concluding.
4. **Review ransomware signals:** alert on sudden file-rename/write spikes, a `.locked` extension, ransom-note creation, disabled backup agents, shadow-copy deletion attempts, endpoint detections, and unusual SMB traffic. Preserve sample paths and timestamps; do not open suspicious files.
5. **Correlate indicators of compromise (IoCs):** source/destination IP, domain/URL, file hash, account ID, host, process, scheduled task, mailbox rule, and certificate. Record observed time, time zone, telemetry source, and confidence. Treat an indicator as a lead, not proof by itself.
6. **Classify P1–P4** using the matrix; set a next update time and list unanswered questions. Ask whether data was accessed/exfiltrated, whether production safety is affected, and whether payment instructions changed.
7. **Preserve volatile evidence:** capture screen/context, logged-in users, relevant process/network state, and volatile memory using an approved trained responder where feasible. Record tools and actions. Do not power off a suspected host unless safety or imminent harm demands it.

Example record format:

| UTC timestamp | Local time / zone | Source | Observation / IoC | Severity | Confidence / action |
|---|---|---|---|---|---|
| 2026-10-19T07:14:00Z | 12:44 IST | M365 audit | Unexpected inbox rule on finance account | P1 | High; preserve audit export |
| 2026-10-19T07:22:00Z | 12:52 IST | VPN gateway | Remote login outside employee's normal hours | P1 | Medium; correlate device and MFA |
| 2026-10-19T07:31:00Z | 13:01 IST | Endpoint alert | Rapid `.locked` file creation on one workstation | P1 | High; isolate host |

## Phase 3 — Containment

### Immediate short-term containment

- Isolate an infected workstation by unplugging Ethernet and disabling Wi-Fi at the endpoint/access point or switch. **Do not power it off** when safe to keep volatile RAM and live state available. Record exact action/time, operator, port, and device identifiers.
- Protect people and production first. Coordinate with the site lead before isolating controllers or safety-critical equipment; use an approved safe-mode/segmentation procedure.
- From a known-clean administrative device, revoke compromised Microsoft 365 refresh/session tokens, reset affected credentials, block malicious inbox rules/OAuth grants, and revoke app passwords. Revoke VPN sessions/credentials and require reauthentication. Preserve relevant audit logs before retention expires.
- Block confirmed command-and-control (C2) IPs/domains at the firewall, DNS, proxy, and email controls. Record the indicator, source, rule, expiry/review date, and expected business impact. Avoid broad blocks based only on low-confidence intelligence.
- Disable compromised accounts and revoke active cloud sessions. Preserve mailbox and identity evidence first when feasible; coordinate with legal/privacy counsel if the action may affect preservation.
- Suspend affected payment changes and independently confirm bank details with known contacts using a previously verified phone number.
- Restrict admin access and protect backups. Disconnect offline media and prevent compromised credentials from reaching backup consoles.

### Longer-term containment

Move known-clean endpoints and services into a clean VLAN with restricted egress and explicit allow-list rules. Separate production, office, backup, guest, server, and management networks. Permit only required ERP, identity, DNS, backup, and portal dependencies. Monitor attempted lateral movement. Keep compromised systems quarantined for evidence and eradication decisions; do not reconnect merely to test them.

## Phase 4 — Eradication

Only begin after the incident scope and evidence preservation are adequate and the IC approves a written eradication plan.

- Identify and remove persistence: malicious scheduled tasks, services, startup entries, rogue local/domain admin accounts, unauthorized OAuth grants and mailbox rules, web shells, malicious DLLs, and unauthorized remote tools. Preserve copies and hashes as evidence before removal.
- Patch the exploited VPN, web portal, endpoint, or cloud integration vulnerability. If a fix is unavailable, disable or restrict the vulnerable path and document compensating controls. Confirm versions against vendor advisories.
- Reset domain, local administrator, service, ERP, VPN, Microsoft 365, API, database, backup, and portal credentials from a known-clean device. Rotate secrets and revoke tokens/certificates that may have been exposed. Do not reuse compromised credentials.
- Review privileged groups, delegated access, conditional access, forwarding rules, remote management, and service principals. Re-enable accounts only after owner verification and MFA enrollment.
- Rebuild systems from trusted, patched images where integrity cannot be established. Scan restored data and validate installation media and configuration baselines.
- Review cryptographic exposure and migration inventory. Replace compromised certificates and keys. Plan transition from classical RSA/ECDSA key establishment/signatures toward NIST post-quantum standards, including **ML-KEM-768** and **ML-DSA-65**, using hybrid/approved deployment guidance where needed. Track **NIST IR 8547 (October 2026)** as a migration-planning reference and verify the current publication and applicable standards with NIST before procurement or compliance claims. Do not claim that a certificate swap alone makes an application quantum-safe.
- Record each change, validation, operator, timestamp, and rollback plan.

## Phase 5 — Recovery

1. IC approves restoration order with business owners: identity and network foundations, backups and monitoring, ERP/accounting, production workflows, email/collaboration, then customer order portal (adjust to documented business impact analysis).
2. Rebuild clean OS images; patch, harden, enroll in monitoring, enable MFA, rotate secrets, and validate endpoint protection before connecting to production.
3. Restore from verified immutable/offline backups in staged waves. Validate backup age, malware scanning, integrity, application consistency, and a sample business transaction. Keep a pre-restore copy for investigation. Never restore a compromised backup console or known-bad image.
4. Test dependencies and access with least privilege. Finance independently verifies invoices and bank instructions; business owners reconcile orders and accounting entries against known-good records.
5. Maintain heightened SIEM/Wazuh, endpoint, identity, firewall, and portal monitoring for **72 hours minimum** after recovery. Review alerts each shift; extend monitoring if indicators recur or scope remains uncertain.
6. Site/IT lead confirms production safety and operational readiness. The business owner signs formal recovery acceptance, including residual risks, open actions, restored services, and monitoring owner. Communicate service status through approved channels.

## Phase 6 — Lessons Learned

Within **five business days** after containment/recovery (or an agreed documented extension), conduct a blameless review with the IC, IT/MSP, affected business owners, legal/privacy counsel, and insurer as appropriate.

- Build a UTC-normalized timeline and root cause analysis (RCA): initial access, enabling conditions, detection gaps, spread, data impact, control failures, and what worked.
- Distinguish confirmed facts, reasonable hypotheses, and unknowns. Do not attribute an attacker without defensible evidence.
- Review customer/employee/regulatory notification duties with counsel and insurer; record decisions, dates, and rationale.
- Update firewall blocks/allow lists, SIEM/Wazuh detection and retention, endpoint controls, identity/MFA policies, VPN/portal patching, backup isolation, and payment verification workflows.
- Retrain relevant staff using the actual pattern without blame or unnecessary exposure of personal data. Test reporting and out-of-band escalation.
- Assign each corrective action an accountable owner, due date, priority, measurable acceptance test, and status. IC confirms closure evidence and signs the report.

### Closure criteria

- [ ] Scope, business impact, evidence inventory, and unresolved uncertainties documented.
- [ ] Compromised access removed; persistence addressed; vulnerable entry point mitigated.
- [ ] Critical services restored from validated sources and formally accepted.
- [ ] Required notifications and insurer/counsel coordination documented.
- [ ] Five-business-day review completed or extension approved.
- [ ] Corrective actions assigned, tracked, and reviewed at the next management meeting.

## Evidence handling quick reference

Preserve original evidence read-only where possible; use a write blocker for removable media where available. Hash at acquisition and after transfer; record SHA3-512 and an independently supported algorithm if policy requires. Record collector, date/time/time zone, source device/account, method/tool version, media ID, transfer, storage location, and each access. Store evidence encrypted with access controls; keep the manifest and report separately from the evidence copy. Hashing alone cannot establish that the collection was complete, authentic, or legally admissible. See [the user manual](../docs/USER_MANUAL.md) and [the walkthrough](REALISTIC_INCIDENT_WALKTHROUGH.md).
