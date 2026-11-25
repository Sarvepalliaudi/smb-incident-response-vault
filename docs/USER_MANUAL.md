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

# smb-ir-vault User Manual

> **Software Architect & Creator:** Sarvepalli Audi Siva Bhanuvardhan  
> **University:** B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester), Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India  
> **Internship:** Cybersecurity Virtual Internship — Dev/Craft by Fennark ([devcraft.fennark.xyz](https://devcraft.fennark.xyz)) | **Intern ID:** DEV-CRAFT-BQ2VPH | **Task 7:** Incident Response Plan  
> **LinkedIn:** [Audi Siva Bhanuvardhan](https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/) | **GitHub:** [Sarvepalliaudi](https://github.com/Sarvepalliaudi)

**Proprietary notice:** Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.

## Purpose and limitations

`smb-ir-vault` combines a six-phase small-business response playbook with a read-only evidence hashing CLI, zero-JavaScript HTML portal, and synthesizable Verilog tamper-seal model. SHA3-512 is a cryptographic integrity digest. A matching digest is not encryption, a digital signature, proof of authorship, proof that acquisition was complete, or a guarantee of legal admissibility. Use approved forensic acquisition and write-blocking procedures and maintain a separate documented custody log.

SHA3-512's 512-bit digest is intended to retain roughly 256-bit preimage security against an idealized Grover search. This estimate does not make the complete evidence workflow quantum-proof or protect against operational, implementation, or custody failures.

The materials are defensive operational guidance, not legal advice. Validate contact data, insurer terms, evidence retention, notification duties, vendor support, and applicable standards for your organization. Never use synthetic sample indicators as live block rules.

## Requirements and build

- Rust stable toolchain and Cargo; network access may be needed on the first build to download the small dependency set.
- Optional `iverilog` to compile/run the self-checking Verilog testbench.
- Windows, Linux, and macOS are supported by the Rust application. The Verilog is portable IEEE Verilog.

```text
cargo test
cargo build --release
```

The release binary is `target/release/smb-ir-vault` (Windows: `target\release\smb-ir-vault.exe`).

## First run and operator profile

Run the program with no subcommand or run an operational command. On first non-web use, it creates `operator_profile.json`, prompts for required **Responder / Operator Name** and **Organization**, then walks through all six guide stages. The profile belongs to the operator; it does not change or replace the separate Software Architect & Creator credit. The profile is local, unencrypted, excluded from version control, and should be protected with appropriate OS access controls.

To re-enter the required values, run `smb-ir-vault --reset-login`; the profile is removed and prompted for again. `--guide` starts the walkthrough on demand. The guide asks `Press ENTER to execute stage...` and explains each phase; it is an educational checklist, not a live action runner. Keep a backup of operational data before removing any local profile.

## CLI usage

### Seal a directory

```text
smb-ir-vault seal --dir ./sample_evidence --incident INC-2026-042
```

This recursively enumerates regular files in deterministic path order, reads and hashes their bytes with SHA3-512, skips symbolic links, and writes `EVIDENCE_MANIFEST.json` and `CHAIN_OF_CUSTODY_REPORT.md` in the current directory. Use `--output <DIR>` to choose another output directory. The tool refuses to overwrite either existing output file, including symlinks. The seal operation does not edit or delete evidence; keep the evidence source read-only and preserve an untouched original.

Each manifest entry has a relative evidence path, size in bytes, and 128-character lowercase SHA3-512 hex digest. The custody report has a compact summary table (short hashes and bounded path cells) and full digests in Section 3. Record acquisition details, transfers, source clock/timezone, and secure storage separately. Do not use a directory containing unrelated secrets.

### Verify

```text
smb-ir-vault verify --manifest ./EVIDENCE_MANIFEST.json
```

The verifier reads each listed file under the manifest's `evidence_root` and reports `[OK] INTACT` or `[ALERT] TAMPERED / MISSING`. It rejects absolute or parent-traversing evidence entry paths and invalid digest shapes. A failure returns a non-zero exit status. Verification uses the evidence root stored in the manifest; run it where that path resolves to the intended evidence copy.

### Interactive guide

```text
smb-ir-vault --guide
```

### Web portal

```text
smb-ir-vault --serve
```

The service listens on `0.0.0.0:8080`; set the `PORT` environment variable to override the port. The portal includes six checklist checkboxes, text hashing, text verification, and a built-in `INC-2026-042` sample manifest check. No browser JavaScript is used. Each evidence form requires responder name and organization; fields start blank and do not assign those values to the creator. Inputs are processed in memory and not persisted by the app. A per-IP in-memory limiter allows five evidence operations per rolling minute; it resets on restart and is not a substitute for a production gateway or identity controls.

The portal trusts its immediate peer address. If deployed behind a proxy, configure proxy-level rate limiting and ensure the service is not directly reachable around that proxy. Do not assume forwarded IP headers are trustworthy. Use TLS at the hosting edge and do not place real evidence in a public demo service.

## Render.com Free Tier

The included `Dockerfile` builds the Rust release binary and includes the synthetic sample-evidence directory. `render.yaml` defines a free web service. Connect the repository to Render and deploy the blueprint; Render supplies `PORT`. The service binds to all interfaces as required for container hosting. The free instance may sleep, restart, and has ephemeral storage; do not rely on it for durable evidence or profile storage. The web service has no login or persistent operator profile and should be used only with synthetic text.

## Six response phases

1. **Preparation:** backups, MFA, centralized telemetry, contact tree, tools, authority.
2. **Detection & Analysis:** preserve time-stamped indicators, scope, severity, and uncertainty.
3. **Containment:** isolate safely, revoke tokens, contain network access, protect backups.
4. **Eradication:** remove persistence, patch, rotate secrets, rebuild where needed.
5. **Recovery:** restore verified clean data in waves, monitor at least 72 hours, obtain owner sign-off.
6. **Lessons Learned:** blameless RCA within five business days, corrective controls and tracked closure.

Read [the full SMB plan](../playbooks/SMB_INCIDENT_RESPONSE_PLAN.md) and [the worked walkthrough](../playbooks/REALISTIC_INCIDENT_WALKTHROUGH.md) before adopting the procedure.

## Verilog Root-of-Trust model

`hardware/forensic_tamper_seal.v` latches a 64-bit digest head on `seal_enable`, locks until active-low `cold_reset_n`, and raises `tamper_violation` on write attempts while locked. Run:

```text
iverilog -g2012 -o tb_forensic_tamper_seal hardware/forensic_tamper_seal.v hardware/tb_forensic_tamper_seal.v
vvp tb_forensic_tamper_seal
```

This is a synthesizable behavioral model, not a certified silicon root of trust. The input digest is a 64-bit illustrative head, not the full SHA3-512 output, and a real design requires secure reset, clock, fault, key, physical attack, and lifecycle analysis.

## Evidence and operator safety

- Keep originals and working copies separate; do not hash a live changing source and treat the result as a forensic acquisition.
- The tool deliberately never writes to or deletes evidence source files. It does write generated output files to the chosen output directory.
- Verify generated manifests immediately; protect them from unauthorized modification and store an independent copy.
- Avoid uploading real customer/employee data to the demo portal. The portal is unauthenticated, does not persist form submissions, and exposes the sample verification route.
- Do not use malware, exploit code, credential-harvesting, or unverified IoCs with this training project. Follow your organization’s incident authority and legal advice.
