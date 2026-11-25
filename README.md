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

# smb-ir-vault — Small Business Incident Response Plan & SHA3-512 Forensic Evidence Vault

**Enterprise-minded, small-business incident response playbooks and a minimal Rust SHA3-512 evidence integrity tool**, paired with a synthesizable Verilog write-once tamper-seal model. This defensive project provides a practical six-phase NIST SP 800-61 Rev. 3-aligned incident response plan for a 35-employee manufacturer, a worked phishing-to-ransomware and invoice-tampering exercise, a custody report template, an interactive plain-text guide, and a zero-JavaScript HTML portal deployable on Render.com Free Tier.

> **Software Architect & Creator:** Sarvepalli Audi Siva Bhanuvardhan  
> **University:** B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester), **Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India**  
> **Internship:** Cybersecurity Virtual Internship — **Dev/Craft by Fennark** ([devcraft.fennark.xyz](https://devcraft.fennark.xyz)) | **Intern ID:** `DEV-CRAFT-BQ2VPH` | **Task 7:** Incident Response Plan  
> **LinkedIn:** [Audi Siva Bhanuvardhan](https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/)  
> **GitHub:** [Sarvepalliaudi](https://github.com/Sarvepalliaudi)

**Proprietary notice:** Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.

## What is included

- **Six-phase SMB incident response plan:** Preparation; Detection & Analysis; Containment; Eradication; Recovery; Lessons Learned.
- **Kaveri Precision Components Pvt. Ltd. scenario:** actionable escalation matrix with P1 15-minute response goals, Windows/Microsoft 365/VPN/cloud ERP/customer portal, finance fraud checks, and safe endpoint containment.
- **Synthetic tabletop walkthrough:** `INC-2026-042` with exact UTC/IST timeline, synthetic telemetry, containment decisions, recovery, and review actions. Sample indicators use reserved `.example` names and RFC documentation IPs only.
- **Rust evidence locker:** deterministic SHA3-512 digesting, sorted read-only traversal, JSON evidence manifest, compact custody report with full hashes, and verification of changed/missing files.
- **Interactive CLI guide and monochrome web portal:** six checklist stages, text hash/verify forms, sample evidence check, no JavaScript, and in-memory five-requests-per-IP-per-minute limiting.
- **Verilog hardware model:** digest-head write-once register, sticky tamper alert, cold-reset behavior, and self-checking testbench.
- **Deployment:** multi-stage `Dockerfile` and Render blueprint for free web hosting. Free hosting is ephemeral and not suitable for real evidence.

## Quick start

Install Rust stable, then from the repository root:

```text
cargo test
cargo build --release
```

First CLI run creates a local `operator_profile.json`, requires the responder's name and organization, and starts the interactive six-phase guide. Those operator fields are distinct from the creator credit. The profile is excluded from Git.

```text
smb-ir-vault --guide
smb-ir-vault seal --dir ./sample_evidence --incident INC-2026-042
smb-ir-vault verify --manifest ./EVIDENCE_MANIFEST.json
smb-ir-vault --serve
```

The web portal listens on `0.0.0.0:8080` or the `PORT` environment variable. Use `smb-ir-vault --reset-login` to re-enter the local CLI operator profile.

The bundled manifest/report are generated from the three safe synthetic artifacts. To create another seal, choose an output directory where the manifest and report do not already exist; the tool refuses to overwrite output files.

## Important forensic limitations

SHA3-512 provides a deterministic cryptographic digest for comparing bytes. It is not a digital signature, encryption, proof of authorship, proof of acquisition completeness, secure storage, or a substitute for documented evidence custody. Preserve originals, record source/time zone/tools/collector/transfers, control access, and use write blockers and trained procedures where appropriate. The tool skips symlinks and does not modify or delete evidence source files; it writes manifest/report outputs to the selected output directory.

The 512-bit digest length is intended to retain roughly 256-bit preimage security against an idealized Grover search; this is a security estimate, not a guarantee of quantum-proof evidence handling or protection against implementation and operational failures.

The Verilog module is an educational synthesizable model. It is not certified silicon, and its 64-bit digest head is illustrative rather than a complete SHA3-512 root of trust. A physical implementation needs threat modeling, secure lifecycle/reset, fault-injection resistance, key management, validation, and independent review.

The portal is unauthenticated, handles text in memory, and is for synthetic/demo data only. Its in-memory rate limit resets on service restart. Place behind a suitable TLS edge and add production authentication, durable audit controls, and gateway-level rate limiting before any real deployment. Render Free Tier storage is ephemeral.

Cryptographic migration guidance mentions ML-KEM-768 and ML-DSA-65 and tracks NIST IR 8547 (October 2026) for planning. Verify current official NIST publications and implementation guidance before procurement or compliance decisions; do not infer quantum safety from a certificate replacement alone.

## Project layout

```text
playbooks/   six-phase plan, incident walkthrough, RCA template
src/         Rust CLI, SHA3-512 evidence locker, zero-JS Axum portal
hardware/    Verilog tamper seal and self-checking testbench
sample_evidence/ safe synthetic artifacts and generated manifest/report
docs/        user manual
Dockerfile   Render-compatible container
render.yaml  Render.com Free Tier service blueprint
LICENSE      MIT terms with additional Authorized Defensive Use Only condition
```

## Verilog simulation

With Icarus Verilog installed:

```text
iverilog -g2012 -o tb_forensic_tamper_seal hardware/forensic_tamper_seal.v hardware/tb_forensic_tamper_seal.v
vvp tb_forensic_tamper_seal
```

Expected output: `[PASS] write-once forensic tamper seal self-checks passed`.

## Render.com deployment

Create a Render Web Service from this repository and deploy `render.yaml` (or use the Dockerfile directly). Render supplies the port; the service binds to all interfaces. Free instances can sleep and have ephemeral storage. Do not upload real evidence, secrets, or customer data.

## Playbooks and documentation

- [SMB Incident Response Plan](playbooks/SMB_INCIDENT_RESPONSE_PLAN.md)
- [Realistic Incident Walkthrough](playbooks/REALISTIC_INCIDENT_WALKTHROUGH.md)
- [Post-Incident RCA Template](playbooks/POST_INCIDENT_REPORT_TEMPLATE.md)
- [User Manual](docs/USER_MANUAL.md)

## License and defensive use

See [LICENSE](LICENSE). It includes MIT text plus an additional **Authorized Defensive Use Only** condition. Follow applicable law, written authorization, your organization's incident authority, and insurer/legal requirements.
