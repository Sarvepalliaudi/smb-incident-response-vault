// smb-ir-vault — Small Business 6-Phase Incident Response Plan & SHA3-512 Forensic Evidence Locker
// Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan.
// B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester),
// Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India.
// Cybersecurity Virtual Internship — Dev/Craft by Fennark: https://devcraft.fennark.xyz
// Intern ID DEV-CRAFT-BQ2VPH, Task 7: Incident Response Plan.
// LinkedIn: https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/
// GitHub: https://github.com/Sarvepalliaudi
// This specification and dual hardware-software architecture is original work created solely for this application.

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

pub const PROPRIETARY_NOTICE: &str = "Specified, architected, and exclusively engineered by Sarvepalli Audi Siva Bhanuvardhan. This specification and dual hardware-software architecture is original work created solely for this application.";
pub const TOOL_NAME: &str =
    "smb-ir-vault (Small Business 6-Phase Incident Response Plan & SHA3-512 Forensic Evidence Locker)";
pub const CREATOR: &str = "Sarvepalli Audi Siva Bhanuvardhan";
pub const UNIVERSITY: &str = "B.Tech Computer Science and Engineering (Cybersecurity), Final Year (7th Semester), Dhanalakshmi Srinivasan University, Tiruchirappalli, Tamil Nadu, India";
pub const INTERNSHIP: &str =
    "Cybersecurity Virtual Internship — Dev/Craft by Fennark | Intern ID: DEV-CRAFT-BQ2VPH | Task 7: Incident Response Plan";
pub const LINKEDIN: &str =
    "https://www.linkedin.com/in/audi-siva-bhanuvardhan-sarvepalli-4598a8289/";
pub const GITHUB: &str = "https://github.com/Sarvepalliaudi";
const MANIFEST_FILE: &str = "EVIDENCE_MANIFEST.json";
const REPORT_FILE: &str = "CHAIN_OF_CUSTODY_REPORT.md";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorProfile {
    pub responder_name: String,
    pub organization: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEntry {
    pub path: String,
    pub size_bytes: u64,
    pub sha3_512: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceManifest {
    pub tool: String,
    pub proprietary_notice: String,
    pub software_architect: String,
    pub university: String,
    pub internship: String,
    pub linkedin: String,
    pub github: String,
    pub incident_id: String,
    pub evidence_root: String,
    pub sealed_at_utc: String,
    pub responder_name: String,
    pub organization: String,
    pub algorithm: String,
    pub entries: Vec<EvidenceEntry>,
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub path: String,
    pub expected: String,
    pub actual: Option<String>,
}

impl VerificationResult {
    pub fn intact(&self) -> bool {
        self.actual
            .as_deref()
            .map(|actual| actual.eq_ignore_ascii_case(&self.expected))
            .unwrap_or(false)
    }
}

pub fn sha3_512_hex(bytes: &[u8]) -> String {
    let digest = Sha3_512::digest(bytes);
    let mut result = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to a String cannot fail");
    }
    result
}

pub fn seal_directory(
    directory: &Path,
    incident_id: &str,
    output_directory: &Path,
    operator: &OperatorProfile,
) -> io::Result<EvidenceManifest> {
    if !directory.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("evidence directory does not exist: {}", directory.display()),
        ));
    }
    if operator.responder_name.trim().is_empty() || operator.organization.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "responder name and organization are required",
        ));
    }

    let manifest_path = output_directory.join(MANIFEST_FILE);
    let report_path = output_directory.join(REPORT_FILE);
    ensure_output_absent(&manifest_path)?;
    ensure_output_absent(&report_path)?;

    let mut paths = Vec::new();
    collect_regular_files(directory, &mut paths)?;
    paths.sort();

    let mut entries = Vec::with_capacity(paths.len());
    for path in paths {
        let relative = path.strip_prefix(directory).map_err(invalid_data)?;
        let relative_string = path_to_manifest_string(relative);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() {
            continue;
        }
        let contents = fs::read(&path)?;
        if metadata.len() != contents.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!(
                    "evidence file changed size while being read: {}",
                    path.display()
                ),
            ));
        }
        entries.push(EvidenceEntry {
            path: relative_string,
            size_bytes: metadata.len(),
            sha3_512: sha3_512_hex(&contents),
        });
    }

    if entries.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no regular evidence files found",
        ));
    }

    let manifest = EvidenceManifest {
        tool: TOOL_NAME.to_owned(),
        proprietary_notice: PROPRIETARY_NOTICE.to_owned(),
        software_architect: CREATOR.to_owned(),
        university: UNIVERSITY.to_owned(),
        internship: INTERNSHIP.to_owned(),
        linkedin: LINKEDIN.to_owned(),
        github: GITHUB.to_owned(),
        incident_id: incident_id.to_owned(),
        evidence_root: path_to_manifest_string(directory),
        sealed_at_utc: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        responder_name: operator.responder_name.trim().to_owned(),
        organization: operator.organization.trim().to_owned(),
        algorithm: "SHA3-512".to_owned(),
        entries,
    };

    fs::create_dir_all(output_directory)?;
    let serialized = serde_json::to_string_pretty(&manifest).map_err(invalid_data)?;
    fs::create_dir_all(output_directory)?;
    write_new_file(&manifest_path, format!("{serialized}\n").as_bytes())?;
    write_new_file(&report_path, render_custody_report(&manifest).as_bytes())?;
    Ok(manifest)
}

fn collect_regular_files(current: &Path, output: &mut Vec<PathBuf>) -> io::Result<()> {
    let mut children = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for entry in children {
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            collect_regular_files(&path, output)?;
        } else if kind.is_file() {
            output.push(path);
        }
    }
    Ok(())
}

fn ensure_output_absent(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("refusing to overwrite existing output: {}", path.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn write_new_file(path: &Path, contents: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(contents)
}

pub fn verify_manifest(manifest_path: &Path) -> io::Result<Vec<VerificationResult>> {
    let contents = fs::read(manifest_path)?;
    let manifest: EvidenceManifest = serde_json::from_slice(&contents).map_err(invalid_data)?;
    let root = Path::new(&manifest.evidence_root);
    if root.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "manifest evidence_root is empty",
        ));
    }

    let mut results = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        let relative = Path::new(&entry.path);
        if !is_safe_relative_path(relative) || !is_valid_sha3_512(&entry.sha3_512) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsafe evidence path or digest in manifest: {}", entry.path),
            ));
        }
        let actual = read_regular_file_without_symlinks(root, relative)?
            .map(|contents| sha3_512_hex(&contents));
        results.push(VerificationResult {
            path: entry.path.clone(),
            expected: entry.sha3_512.clone(),
            actual,
        });
    }
    Ok(results)
}

fn read_regular_file_without_symlinks(root: &Path, relative: &Path) -> io::Result<Option<Vec<u8>>> {
    let components = relative.components().collect::<Vec<_>>();
    let mut current = root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Ok(None);
        };
        current.push(name);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if metadata.file_type().is_symlink() {
            return Ok(None);
        }
        let is_last = index + 1 == components.len();
        if is_last && !metadata.file_type().is_file() {
            return Ok(None);
        }
        if !is_last && !metadata.file_type().is_dir() {
            return Ok(None);
        }
    }
    fs::read(current).map(Some)
}

fn is_safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn is_valid_sha3_512(digest: &str) -> bool {
    digest.len() == 128 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn path_to_manifest_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

pub fn render_custody_report(manifest: &EvidenceManifest) -> String {
    let mut report = format!(
        "# Chain of Custody — {}\n\n\
         > {}\n\n\
         **Software Architect:** {}  \n\
         **University:** {}  \n\
         **Internship:** {}  \n\
         **LinkedIn:** {}  \n\
         **GitHub:** {}  \n\
         **Incident:** {}  \n\
         **Sealed (UTC):** {}  \n\
         **Responder:** {}  \n\
         **Organization:** {}  \n\
         **Algorithm:** {}\n\n\
         ## 1. Handling record\n\n\
         Evidence was read-only hashed from `{}`. Symlinks were skipped. \
         Keep the original media and this report under separate access controls. \
         SHA3-512 detects changes; it does not prove acquisition authenticity or replace \
         write-blocking, secure storage, or a documented transfer process.\n\n\
         ## 2. Compact evidence summary\n\n\
         | Evidence path | Bytes | SHA3-512 (short) |\n\
         |---|---:|---|\n",
        manifest.incident_id,
        manifest.proprietary_notice,
        manifest.software_architect,
        manifest.university,
        manifest.internship,
        manifest.linkedin,
        manifest.github,
        manifest.incident_id,
        manifest.sealed_at_utc,
        manifest.responder_name,
        manifest.organization,
        manifest.algorithm,
        manifest.evidence_root,
    );
    for entry in &manifest.entries {
        let path = compact_cell(&entry.path, 36);
        let short_hash = format!("{}…", &entry.sha3_512[..16]);
        report.push_str(&format!(
            "| {path} | {} | {short_hash} |\n",
            entry.size_bytes
        ));
    }
    report.push_str("\n## 3. Full SHA3-512 digests\n\n| Evidence path | SHA3-512 |\n|---|---|\n");
    for entry in &manifest.entries {
        report.push_str(&format!(
            "| {} | `{}` |\n",
            compact_cell(&entry.path, 36),
            entry.sha3_512
        ));
    }
    report.push_str(
        "\n## 4. Custody attestations\n\n\
         | Event | Person | Organization | UTC timestamp | Notes |\n\
         |---|---|---|---|---|\n\
         | Acquisition / sealing |  |  |  | Record source and method |\n\
         | Transfer / storage |  |  |  | Record recipient and secure location |\n\
         | Verification |  |  |  | Record manifest and result |\n",
    );
    report
}

fn compact_cell(value: &str, max_chars: usize) -> String {
    let clean = value
        .replace('|', "\\|")
        .replace('\n', " ")
        .replace('\r', " ");
    let mut chars = clean.chars();
    let compact: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{compact}…")
    } else {
        compact
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn sha3_512_matches_known_empty_input_vector() {
        assert_eq!(
            sha3_512_hex(b""),
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
             15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
                .replace(' ', "")
        );
    }

    #[test]
    fn seal_and_verify_detect_a_changed_artifact() {
        let base = std::env::temp_dir().join(format!(
            "smb-ir-vault-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        let evidence = base.join("evidence");
        let output = base.join("output");
        fs::create_dir_all(&evidence).expect("create evidence");
        fs::write(evidence.join("note.txt"), "synthetic evidence").expect("write fixture");
        let profile = OperatorProfile {
            responder_name: "Test Responder".to_owned(),
            organization: "Test Org".to_owned(),
        };
        let manifest = seal_directory(&evidence, "TEST-1", &output, &profile).expect("seal");
        let manifest_path = output.join(MANIFEST_FILE);
        assert!(verify_manifest(&manifest_path)
            .expect("verify")
            .iter()
            .all(VerificationResult::intact));
        fs::write(evidence.join("note.txt"), "modified").expect("modify fixture");
        let results = verify_manifest(&manifest_path).expect("verify modified");
        assert_eq!(results.len(), manifest.entries.len());
        assert!(!results[0].intact());
        fs::remove_dir_all(base).expect("remove test fixture");
    }

    #[test]
    fn manifest_paths_cannot_escape_the_evidence_root() {
        assert!(!is_safe_relative_path(Path::new("../outside.txt")));
        assert!(!is_safe_relative_path(Path::new("/outside.txt")));
        assert!(is_safe_relative_path(Path::new("nested/evidence.txt")));
    }

    #[test]
    fn sealing_refuses_to_overwrite_existing_output_files() {
        let base = std::env::temp_dir().join(format!(
            "smb-ir-vault-output-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        let evidence = base.join("evidence");
        let output = base.join("output");
        fs::create_dir_all(&evidence).expect("create evidence");
        fs::create_dir_all(&output).expect("create output");
        fs::write(evidence.join("note.txt"), "synthetic evidence").expect("write fixture");
        let manifest_path = output.join(MANIFEST_FILE);
        fs::write(&manifest_path, "preserve existing file").expect("create sentinel");
        let profile = OperatorProfile {
            responder_name: "Test Responder".to_owned(),
            organization: "Test Org".to_owned(),
        };
        let error = seal_directory(&evidence, "TEST-2", &output, &profile)
            .expect_err("existing manifest must not be overwritten");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read_to_string(&manifest_path).expect("read sentinel"),
            "preserve existing file"
        );
        fs::remove_dir_all(base).expect("remove test fixture");
    }
}
