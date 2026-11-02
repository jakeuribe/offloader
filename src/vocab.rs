//! Fixed vocabulary: every name the program knows lives here.

pub const PROGRAM: &str = "offloader";
pub const RECORD_MAGIC: &str = "offloader-v1";
pub const DEFAULT_EXT: &str = "offload";
/// Hidden temp file next to the restore target, renamed into place when complete.
pub const PARTIAL_PREFIX: &str = ".offloader-partial-";
pub const TMP_PREFIX: &str = "offloader-";
pub const BLOB_NAME: &str = "blob";
pub const VERIFY_NAME: &str = "verify";
pub const SHELL: &str = "sh";
pub const SHELL_FLAG: &str = "-c";
pub const RECORD_SEP: char = '=';
pub const ID_BYTES: usize = 16;
pub const COMPARE_BUF: usize = 64 * 1024;
pub const PRIVATE_FILE_MODE: u32 = 0o600;
pub const PRIVATE_DIR_MODE: u32 = 0o700;
/// Permission bits carried in the record (rwx for u/g/o + setuid/setgid/sticky).
pub const MODE_MASK: u32 = 0o7777;
pub const MODE_RADIX: u32 = 8;
pub const PROMPT_PASS: &str = "record passphrase: ";
pub const PROMPT_CONFIRM: &str = "confirm passphrase: ";
pub const METHOD_DIR: &str = "dir";
pub const METHOD_SHELL: &str = "shell";

/// Long flag names (without the leading `--`).
pub mod flag {
    pub const METHOD: &str = "method";
    pub const DIR: &str = "dir";
    pub const PUT: &str = "put";
    pub const GET: &str = "get";
    pub const RM: &str = "rm";
    pub const EXT: &str = "ext";
    pub const TMP: &str = "tmp";
    pub const NO_VERIFY: &str = "no-verify";
    pub const PURGE: &str = "purge";
    pub const NO_PURGE: &str = "no-purge";
}

/// Env var fallbacks for flags, plus the passphrase.
pub mod env {
    pub const METHOD: &str = "OFFLOADER_METHOD";
    pub const DIR: &str = "OFFLOADER_DIR";
    pub const PUT: &str = "OFFLOADER_PUT";
    pub const GET: &str = "OFFLOADER_GET";
    pub const RM: &str = "OFFLOADER_RM";
    pub const EXT: &str = "OFFLOADER_EXT";
    pub const TMP: &str = "OFFLOADER_TMP";
    pub const NO_VERIFY: &str = "OFFLOADER_NO_VERIFY";
    pub const PURGE: &str = "OFFLOADER_PURGE";
    pub const PASSPHRASE: &str = "OFFLOADER_PASSPHRASE";
}
