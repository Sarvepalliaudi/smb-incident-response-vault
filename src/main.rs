// smb-ir-vault — Small Business 6-Phase Incident Response Plan & SHA3-512 Forensic Evidence Locker
// Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan.
// B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester),
// Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India.
// Cybersecurity Virtual Internship — Dev/Craft by Fennark: https://devcraft.fennark.xyz
// Intern ID DEV-CRAFT-BQ2VPH, Task 7: Incident Response Plan.
// LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/
// GitHub: https://github.com/Sarvepalliaudi
// Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan.
// This specification and dual hardware-software architecture is original work created solely for this application.

mod locker;
mod web;

use clap::{Parser, Subcommand};
use locker::{OperatorProfile, PROPRIETARY_NOTICE, TOOL_NAME};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const PROFILE_FILE: &str = "operator_profile.json";

#[derive(Debug, Parser)]
#[command(name = "smb-ir-vault", version, about = TOOL_NAME)]
struct Cli {
    #[arg(
        long,
        global = true,
        help = "Walk through the six IR phases and hashing"
    )]
    guide: bool,
    #[arg(long, global = true, help = "Start the web portal on 0.0.0.0:$PORT")]
    serve: bool,
    #[arg(
        long,
        global = true,
        help = "Clear and re-enter the required responder profile"
    )]
    reset_login: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(about = "Read-only hash evidence and write a manifest and custody report")]
    Seal {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        incident: String,
        #[arg(long, default_value = ".")]
        output: PathBuf,
    },
    #[command(about = "Re-hash evidence listed in a manifest")]
    Verify {
        #[arg(long)]
        manifest: PathBuf,
    },
    #[command(about = "Serve the monochrome incident-response and evidence portal")]
    Serve,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_banner();
    let cli = Cli::parse();
    if cli.reset_login {
        clear_profile(Path::new(PROFILE_FILE))?;
    }

    if cli.serve || matches!(&cli.command, Some(Command::Serve)) {
        web::serve().await?;
        return Ok(());
    }

    match cli.command {
        command => {
            let (profile, first_run) = load_or_prompt_profile(Path::new(PROFILE_FILE))?;
            if cli.guide || first_run {
                run_guide()?;
            }
            match command {
                Some(Command::Seal {
                    dir,
                    incident,
                    output,
                }) => {
                    let manifest = locker::seal_directory(&dir, &incident, &output, &profile)?;
                    println!(
                        "[OK] Sealed {} files for {} using SHA3-512.",
                        manifest.entries.len(),
                        manifest.incident_id
                    );
                    println!(
                        "[OK] Wrote {} and {}",
                        output.join("EVIDENCE_MANIFEST.json").display(),
                        output.join("CHAIN_OF_CUSTODY_REPORT.md").display()
                    );
                }
                Some(Command::Verify { manifest }) => {
                    let results = locker::verify_manifest(&manifest)?;
                    let mut intact = true;
                    for result in &results {
                        if result.intact() {
                            println!("[OK] INTACT  {}", result.path);
                        } else {
                            intact = false;
                            println!("[ALERT] TAMPERED / MISSING  {}", result.path);
                        }
                    }
                    if results.is_empty() {
                        return Err("manifest contains no evidence entries".into());
                    }
                    if !intact {
                        return Err("one or more evidence items failed verification".into());
                    }
                }
                None => print_usage_hint(),
                Some(Command::Serve) => unreachable!("serve handled before profile setup"),
            }
        }
    }
    Ok(())
}

fn print_banner() {
    println!(
        "{TOOL_NAME}\n\
         Software Architect & Creator: Sarvepalli Audi Siva Bhanuvardhan\n\
         University: B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester), \
         Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India\n\
         Internship: Cybersecurity Virtual Internship — Dev/Craft by Fennark (https://devcraft.fennark.xyz) | \
         Intern ID: DEV-CRAFT-BQ2VPH | Task 7: Incident Response Plan\n\
         LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/\n\
         GitHub: https://github.com/Sarvepalliaudi\n\
         {PROPRIETARY_NOTICE}\n\
         Defensive incident response and read-only evidence hashing. SHA3-512 is an integrity \
         digest, not a signature or proof of chain of custody."
    );
}

fn load_or_prompt_profile(
    path: &Path,
) -> Result<(OperatorProfile, bool), Box<dyn std::error::Error>> {
    if path.exists() {
        let mut profile: OperatorProfile = serde_json::from_slice(&fs::read(path)?)?;
        let mut first_run = false;
        if profile.responder_name.trim().is_empty() {
            profile.responder_name = prompt_required("Responder / Operator Name")?;
            first_run = true;
        }
        if profile.organization.trim().is_empty() {
            profile.organization = prompt_required("Organization")?;
            first_run = true;
        }
        if first_run {
            fs::write(
                path,
                format!("{}\n", serde_json::to_string_pretty(&profile)?),
            )?;
        }
        return Ok((profile, first_run));
    }

    let mut profile = OperatorProfile {
        responder_name: String::new(),
        organization: String::new(),
    };
    let initial = serde_json::to_string_pretty(&profile)?;
    fs::write(path, format!("{initial}\n"))?;
    println!("\nFirst run: responder attribution is separate from software-creator credit.");
    profile.responder_name = prompt_required("Responder / Operator Name")?;
    profile.organization = prompt_required("Organization")?;
    fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(&profile)?),
    )?;
    Ok((profile, true))
}

fn clear_profile(path: &Path) -> io::Result<()> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn prompt_required(label: &str) -> Result<String, Box<dyn std::error::Error>> {
    loop {
        print!("{label} (required): ");
        io::stdout().flush()?;
        let mut value = String::new();
        if io::stdin().read_line(&mut value)? == 0 {
            return Err("interactive profile setup requires a terminal; populate operator_profile.json and retry".into());
        }
        let value = value.trim().to_owned();
        if !value.is_empty() {
            return Ok(value);
        }
        println!("This value is required.");
    }
}

fn run_guide() -> io::Result<()> {
    let phases = [
        (
            "Phase 1 — Preparation",
            "Maintain offline encrypted 3-2-1 backups, MFA, centralized telemetry, a forensic jump bag, and pre-approved containment authority.",
        ),
        (
            "Phase 2 — Detection & Analysis",
            "Preserve exact timestamps and classify the incident; correlate phishing, unusual VPN/RDP logins, file-extension spikes, and IoCs.",
        ),
        (
            "Phase 3 — Containment",
            "Isolate affected hosts without powering them off, revoke compromised sessions, block confirmed C2 indicators, and segment clean systems.",
        ),
        (
            "Phase 4 — Eradication",
            "Remove persistence, patch the exploited entry point, reset credentials, and plan cryptographic modernization.",
        ),
        (
            "Phase 5 — Recovery",
            "Rebuild clean systems, restore verified immutable backups in waves, monitor closely, and obtain owner approval.",
        ),
        (
            "Phase 6 — Lessons Learned",
            "Run a blameless review within five business days, document root cause, tune controls, retrain, and close tracked actions.",
        ),
    ];
    println!("\nInteractive response guide (consult the full playbook before acting).");
    for (phase, action) in phases {
        println!("\n{phase}\n{action}");
        wait_for_enter()?;
    }
    println!(
        "\nForensic hashing demonstration: SHA3-512 of the empty byte string = {}",
        locker::sha3_512_hex(b"")
    );
    println!(
        "Use `smb-ir-vault seal --dir <evidence-directory> --incident <incident-id>` to seal."
    );
    Ok(())
}

fn wait_for_enter() -> io::Result<()> {
    print!("Press ENTER to execute stage...");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(())
}

fn print_usage_hint() {
    println!(
        "\nCommands: seal --dir <DIR> --incident <ID> [--output <DIR>], \
         verify --manifest <FILE>, --serve; use --guide for the six-phase walkthrough."
    );
}
