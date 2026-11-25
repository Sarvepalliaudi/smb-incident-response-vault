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

# Worked Scenario: Phishing-to-Ransomware & Invoice-Tampering

**Scenario only:** Kaveri Precision Components Pvt. Ltd. (KPC), 35 employees. Incident **INC-2026-042**, Monday 19 October 2026. All people, domains, IPs, logs, artifacts, and events below are synthetic training material. The reserved `.example` domain and documentation IP ranges are non-routable examples. This is not a claim about a real organization or breach.

**Environment:** Windows endpoints; cloud ERP/accounting server; Microsoft 365 email and identity; customer order portal; VPN access; segmented production network; MSSP-managed Wazuh/syslog; offline immutable backups. Roles are used rather than real contact details.

## Situation and initial evidence

At 12:44 IST, Finance reports an email requesting an urgent supplier bank-account change. A finance employee opened an attached spreadsheet and entered Microsoft 365 credentials on a look-alike training domain. The mailbox was used to alter an invoice conversation. A compromised VPN identity then accessed a finance workstation; ransomware began renaming files with `.locked`. The MSSP observes suspicious remote access and endpoint activity. The team does not assume the portal or ERP was compromised; both are investigated.

### Synthetic event timeline (UTC / IST)

| UTC | IST | Source / event | Decision / evidence |
|---|---|---|---|
| 2026-10-19 07:14:00Z | 12:44 | Finance reports invoice bank-change email received; message preserved as `.eml` and headers exported | IC opens INC-2026-042, provisionally P1 due to suspected credential theft and payment fraud |
| 07:18:00Z | 12:48 | User confirms spreadsheet opened and credentials submitted; MFA push approved after prompt | Preserve user account, email, endpoint, message, and sign-in audit data |
| 07:22:16Z | 12:52 | VPN gateway logs successful sign-in to `FIN-WS-07` from documentation address `198.51.100.27`, outside user's normal hours | P1; identity and VPN administrator correlate account/device/session |
| 07:25:41Z | 12:55 | M365 audit shows new inbox rule forwarding matching invoice messages; no forwarding destination is published in this sample | Export audit and rule details before disabling; legal/privacy notified |
| 07:31:08Z | 13:01 | Wazuh alert: rapid file-write/rename activity and `.locked` extension spike on `FIN-WS-07` | P1 confirmed; site lead confirms host is not production control equipment |
| 07:33:00Z | 13:03 | IT disconnects Ethernet and disables Wi-Fi on `FIN-WS-07`; workstation left powered on | Short-term containment; operator, switch port, and time logged |
| 07:36:20Z | 13:06 | M365 admin revokes finance account sessions, blocks sign-in pending reset, removes forwarding rule after evidence export | Stop access; preserve audit exports; verify clean admin device |
| 07:39:10Z | 13:09 | VPN admin revokes active session and disables compromised VPN credential | Search same credential across recent VPN events |
| 07:44:00Z | 13:14 | Firewall blocks confirmed training-domain indicator at DNS/proxy and email gateway; no C2 IP block is made without confirmed indicator | Record rule and review time; do not use the example IP as a real block |
| 07:52:00Z | 13:22 | MSSP finds no second endpoint with `.locked` writes; identity audit review continues | Scope is one endpoint, but account access remains under investigation |
| 08:05:00Z | 13:35 | Finance pauses supplier bank changes; known supplier contacted using verified phone details from existing records | Payment fraud exposure contained; bank notified for monitoring |
| 08:40:00Z | 14:10 | Legal and insurer/breach coach contacted using offline policy contacts | Confirm evidence preservation and approved forensic support |
| 10:15:00Z | 15:45 | Clean VLAN prepared; compromised endpoint remains quarantined and powered for trained collection | IC authorizes forensic acquisition before rebuild |
| 13:20:00Z | 18:50 | Credential sweep identifies no evidence of ERP/portal admin access; checks continue | Provisional scope remains finance identity/workstation |
| 2026-10-20 04:00:00Z | 09:30 | Trusted image rebuild and staged restore begin after evidence capture and approval | Recovery gate: clean credentials, patch, monitoring, validated backup |
| 2026-10-20 10:00:00Z | 15:30 | Finance validates reconciled invoice and supplier bank details; business owner signs service acceptance | Resume payment workflow with dual verification |
| 2026-10-23 10:00:00Z | 15:30 | 72-hour heightened monitoring passes with no recurrence; close operational recovery | P2/P1 status reviewed by IC; post-incident review scheduled |
| 2026-10-26 05:00:00Z | 10:30 | Blameless review held within five business days of discovery | Actions assigned and closure criteria tracked |

## Phase 1 — Preparation

**Before the event:** KPC's offline contact sheet identifies the business owner as IC, IT/MSP, M365 admin, site lead, finance lead, counsel, and insurer. The business has tested immutable backups, MFA on M365/VPN/admin access, Wazuh/syslog forwarding, and an approved endpoint-isolation procedure. The MSSP has a 15-minute P1 acknowledgement target. A sealed jump bag and paper evidence forms are stored away from the production network.

**Decision at discovery:** Finance calls the IC using the offline call tree rather than replying to the email. Because a credential was entered and an invoice is affected, the IC chooses P1 and mobilizes the team within the 15-minute target. Any missed contact is escalated to the alternate.

## Phase 2 — Detection & Analysis

**Exact synthetic initial records:**

```text
2026-10-19T07:14:00Z m365-mail message_id=MSG-SYN-042 sender=accounts@vendor-check.example subject="Updated remittance details" attachment=Remittance_Advice.xlsx recipient=finance@kaveri.example
2026-10-19T07:18:00Z user-report user=finance-01 action=attachment_opened credential_submitted mfa_approved=true
2026-10-19T07:22:16Z vpn-gateway account=finance-01 result=success source_ip=198.51.100.27 target=FIN-WS-07
2026-10-19T07:25:41Z m365-audit account=finance-01 event=inbox_rule_created rule_name=InvoiceReview action=forward_matching_messages
2026-10-19T07:31:08Z wazuh endpoint=FIN-WS-07 alert=file_rename_rate_high extension=.locked severity=critical
```

**Actions:** preserve original message and full headers; export M365 audit and sign-in records; note the system clock/time zone; collect EDR/Wazuh alert details and the workstation's logged-in user/process/network state through the trained responder. Search VPN, M365, ERP, portal, and firewall logs for the user, source address, and event window. Treat `198.51.100.27` as documentation-only; never block it as if it were an actual IoC. Classify P1 with high confidence for ransomware on the endpoint and medium confidence for the full account/data scope.

**What is not concluded:** message origin, exact data viewed, and whether any information left the tenant remain unknown until audit and provider logs are reviewed. A lack of a detection alert is not proof of no access.

## Phase 3 — Containment

**07:33Z:** IT disconnects `FIN-WS-07` from Ethernet and Wi-Fi, records the operator and switch port, leaves power on, and restricts physical access. This avoids unnecessary volatile-memory loss. Site lead confirms that this is a finance workstation, not a machine controller.

**07:36–07:44Z:** After preserving available M365 audit and inbox-rule details, the clean-device M365 admin revokes sessions and suspends the identity. VPN admin ends the session and disables the credential. The MSSP searches for other use of the identity. Confirmed malicious training-domain indicators are blocked in DNS/proxy and mail filtering with a review date; no speculative IP block is added.

Finance freezes invoice changes and calls the supplier using the existing verified phone number. The bank's fraud team is contacted if payment has been initiated. The IC authorizes a clean VLAN for known-good systems; the affected workstation remains isolated. The backup administrator confirms offline media is disconnected from the compromised identity.

## Phase 4 — Eradication

The responder preserves relevant volatile and disk evidence using approved procedures, records each tool and transfer, and seals read-only working copies with `smb-ir-vault`. The team retains the original device; it is not wiped during acquisition.

The MSP reviews persistence, privileged-account changes, scheduled tasks, services, unauthorized DLLs/tools, mailbox rules, OAuth grants, and VPN use. It finds the forwarding rule and compromised identity but no evidence of persistence on other assets in this synthetic scenario. The endpoint is rebuilt from a trusted image. M365/VPN, local/domain, ERP, service, and backup credentials in the suspected exposure path are reset or rotated from a clean administrative device; MFA is re-verified. The malicious message pattern, tenant controls, and user-reporting path are updated.

IT verifies patch status for VPN and the order portal; no exploited portal vulnerability is asserted in this scenario. Certificate/key exposure is assessed. KPC records a quantum-readiness work item to inventory RSA/ECDSA certificates and plan a standards-based migration review for ML-KEM-768 and ML-DSA-65, consulting current NIST IR 8547 (October 2026) and applicable implementation guidance. It does not claim that this response exercise itself deploys post-quantum cryptography.

## Phase 5 — Recovery

At 04:00Z on 20 October, the IC approves a staged rebuild/restore after evidence preservation. IT rebuilds the finance workstation, patches it, enrolls endpoint monitoring, verifies MFA, rotates relevant credentials, and tests access using least privilege. The MSSP watches identity, endpoint, firewall, VPN, ERP, M365, and portal telemetry.

The team restores only necessary finance data from an immutable backup whose integrity and timestamp are checked; a separate clean copy remains preserved for analysis. Finance reconciles the disputed invoice and bank details with the supplier using a known-good contact. Two-person approval is required for payment changes. The business owner signs the recovery record at 10:00Z after the finance workflow and customer order portal are tested.

Heightened SIEM/endpoint monitoring continues for at least 72 hours after service restoration, through 10:00Z on 23 October. Every shift records alert review and escalates any renewed sign-in or file-write indicator. No recurrence is observed in this synthetic timeline.

## Phase 6 — Lessons Learned

On 26 October (within five business days of discovery), the team conducts a blameless RCA. The immediate access path was a credential submitted after a phishing attachment led to a look-alike sign-in. MFA approval reduced friction for the attacker; invoice changes lacked an independent callback at the time. This describes control conditions, not individual fault.

**Actions and owners:**

| Action | Owner | Due / acceptance evidence |
|---|---|---|
| Require phishing-resistant MFA for finance/admin where supported; review conditional access | M365 administrator | 30 days; test sign-in policy and retain change record |
| Add alert for after-hours VPN sign-in plus suspicious endpoint activity | MSSP | 14 days; replay synthetic test and capture alert |
| Enforce independent supplier bank-change callback and dual approval | Finance lead | 7 days; revised procedure and sample audit |
| Review mailbox forwarding/OAuth alerts and audit retention | M365 administrator | 14 days; saved query and test event |
| Run targeted phishing reporting refresher | People/finance lead | 30 days; attendance and reporting exercise |
| Test offline restore and document clean recovery order | IT/MSP and site lead | 30 days; successful restore record |
| Inventory RSA/ECDSA certificates and assess NIST PQC migration | IT/MSP | 90 days; owner-approved inventory and roadmap |

The IC tracks due dates, verifies evidence of completion, and records residual risk. Notification, privacy, and insurer decisions are documented with counsel; this sample intentionally invents no legal conclusion.
