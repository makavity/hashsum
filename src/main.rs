use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read},
    process,
};

use clap::{Parser, ValueEnum};
use digest::{Digest, DynDigest};

const STDIN_NAME: &str = "-";

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Algorithm {
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    #[value(name = "belt-hash")]
    BeltHash,
}

/// Print or check cryptographic checksums
#[derive(Parser, Debug)]
#[command(name = "hashsum")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Print or check cryptographic checksums", long_about = None)]
struct Args {
    /// Files to process (use '-' for stdin)
    #[arg(value_name = "FILE")]
    files: Vec<String>,

    /// Read checksums from files and verify them
    #[arg(short, long)]
    check: bool,

    /// Hash algorithm to use
    #[arg(short, long, value_enum, default_value = "md5")]
    algorithm: Algorithm,

    /// Don't fail for missing files (only with --check)
    #[arg(long, requires = "check")]
    ignore_missing: bool,

    /// Don't print OK for verified files (only with --check)
    #[arg(short, long, requires = "check")]
    quiet: bool,

    /// Don't output anything, use exit code only (only with --check)
    #[arg(long, requires = "check")]
    status: bool,

    /// Exit non-zero for malformed lines (only with --check)
    #[arg(long, requires = "check")]
    strict: bool,

    /// Warn about malformed lines (only with --check)
    #[arg(short, long, requires = "check")]
    warn: bool,
}

impl Args {
    fn files(&self) -> Vec<&str> {
        if self.files.is_empty() {
            vec![STDIN_NAME]
        } else {
            self.files.iter().map(|s| s.as_str()).collect()
        }
    }
}

#[derive(Debug)]
enum CheckResult {
    Success,
    Failed(String),
    BadFormat,
    ReadError(String, io::Error),
}

fn main() {
    let args = Args::parse();
    let filenames = args.files();

    if args.check {
        check_mode(&filenames, &args);
    } else {
        hash_mode(&filenames, &args);
    }
}

fn hash_mode(filenames: &[&str], args: &Args) {
    for filename in filenames {
        match compute_hash(filename, args.algorithm) {
            Ok(digest) => {
                println!("{}  {}", digest, filename);
            }
            Err(e) => {
                if !args.quiet {
                    eprintln!("Error reading '{}': {}", filename, e);
                }
                process::exit(1);
            }
        }
    }
}

fn check_mode(filenames: &[&str], args: &Args) {
    let mut failed = Vec::new();

    for filename in filenames {
        match open_reader(filename) {
            Ok(reader) => {
                for (line_num, line) in reader.lines().enumerate() {
                    match line {
                        Ok(line) => match verify_line(&line, args) {
                            CheckResult::Success => {
                                if !args.quiet && !args.status {
                                    // Print the checked file name on success
                                    if let Some((_, checked_file)) = parse_checksum_line(&line) {
                                        println!("{}: OK", checked_file);
                                    }
                                }
                            }
                            CheckResult::Failed(file) => {
                                if !args.status {
                                    eprintln!("{}: FAILED", file);
                                }
                                failed.push(file);
                            }
                            CheckResult::BadFormat => {
                                if args.strict {
                                    eprintln!(
                                        "{}:{}: improperly formatted checksum line",
                                        filename,
                                        line_num + 1
                                    );
                                    process::exit(1);
                                } else if args.warn && !args.quiet {
                                    eprintln!(
                                        "{}:{}: WARNING: improperly formatted line",
                                        filename,
                                        line_num + 1
                                    );
                                }
                            }
                            CheckResult::ReadError(file, err) => {
                                if !args.ignore_missing {
                                    eprintln!("Failed to read '{}': {}", file, err);
                                    process::exit(1);
                                }
                            }
                        },
                        Err(e) => {
                            eprintln!("Error reading line from '{}': {}", filename, e);
                            process::exit(1);
                        }
                    }
                }
            }
            Err(e) => {
                if !args.ignore_missing {
                    eprintln!("Failed to open '{}': {}", filename, e);
                    process::exit(1);
                }
            }
        }
    }

    if !failed.is_empty() {
        if !args.status {
            let plural = if failed.len() > 1 { "s" } else { "" };
            eprintln!(
                "WARNING: {} computed checksum{} did NOT match",
                failed.len(),
                plural
            );
        }
        process::exit(1);
    }
}

fn verify_line(line: &str, args: &Args) -> CheckResult {
    match parse_checksum_line(line) {
        Some((expected_hash, filename)) => match compute_hash(filename, args.algorithm) {
            Ok(actual_hash) => {
                if expected_hash.eq_ignore_ascii_case(&actual_hash) {
                    CheckResult::Success
                } else {
                    CheckResult::Failed(filename.to_string())
                }
            }
            Err(e) => CheckResult::ReadError(filename.to_string(), e),
        },
        _ => CheckResult::BadFormat,
    }
}

fn parse_checksum_line(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    // Format: <hash><space><space or *><filename>
    // Try double space format first
    if let Some((hash, filename)) = line.split_once("  ") {
        if is_valid_hex(hash) {
            return Some((hash, filename));
        }
    }

    // Try single space with * or space prefix
    if let Some((hash, rest)) = line.split_once(' ') {
        if is_valid_hex(hash) && (rest.starts_with(' ') || rest.starts_with('*')) {
            return Some((hash, &rest[1..]));
        }
    }

    None
}

fn is_valid_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn compute_hash(filename: &str, algorithm: Algorithm) -> io::Result<String> {
    let mut reader = open_reader(filename)?;
    let mut hasher = create_hasher(algorithm)?;

    let mut buffer = [0u8; 8192];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(hex::encode(hasher.finalize_reset()))
}

fn create_hasher(algorithm: Algorithm) -> io::Result<Box<dyn DynDigest>> {
    let hasher: Box<dyn DynDigest> = match algorithm {
        Algorithm::Md5 => Box::new(md5::Md5::new()),
        Algorithm::Sha1 => Box::new(sha1::Sha1::new()),
        Algorithm::Sha224 => Box::new(sha2::Sha224::new()),
        Algorithm::Sha256 => Box::new(sha2::Sha256::new()),
        Algorithm::Sha384 => Box::new(sha2::Sha384::new()),
        Algorithm::Sha512 => Box::new(sha2::Sha512::new()),
        Algorithm::BeltHash => Box::new(belt_hash::BeltHash::new()),
    };
    Ok(hasher)
}

fn open_reader(filename: &str) -> io::Result<Box<dyn BufRead>> {
    if filename == STDIN_NAME {
        Ok(Box::new(BufReader::new(io::stdin())))
    } else {
        let file = File::open(filename)?;
        Ok(Box::new(BufReader::new(file)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_lines() {
        let cases = vec![
            (
                "d41d8cd98f00b204e9800998ecf8427e  file.txt",
                Some(("d41d8cd98f00b204e9800998ecf8427e", "file.txt")),
            ),
            (
                "d41d8cd98f00b204e9800998ecf8427e *file.txt",
                Some(("d41d8cd98f00b204e9800998ecf8427e", "file.txt")),
            ),
            (
                "D41D8CD98F00B204E9800998ECF8427E  file.txt",
                Some(("D41D8CD98F00B204E9800998ECF8427E", "file.txt")),
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(
                parse_checksum_line(input),
                expected,
                "Failed for: {}",
                input
            );
        }
    }

    #[test]
    fn test_parse_invalid_lines() {
        let invalid = vec![
            "",
            "# comment",
            "not-hex  file.txt",
            "d41d8cd98f00b204e9800998ecf8427e",
            "d41d8cd98f00b204e9800998ecf8427e-file.txt",
        ];

        for input in invalid {
            assert_eq!(
                parse_checksum_line(input),
                None,
                "Should be invalid: {}",
                input
            );
        }
    }

    #[test]
    fn test_is_valid_hex() {
        assert!(is_valid_hex("abc123"));
        assert!(is_valid_hex("ABC123"));
        assert!(is_valid_hex("0123456789abcdefABCDEF"));
        assert!(!is_valid_hex(""));
        assert!(!is_valid_hex("xyz"));
        assert!(!is_valid_hex("12 34"));
    }
}
