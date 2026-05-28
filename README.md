# Vault

A lightweight Windows file & folder encryption tool. Single executable, zero installation.

## Features

- **Directory Mode** — Place the exe in any folder, run it, and encrypt/decrypt everything inside with one click. File and directory names are also encrypted.
- **Single File Mode** — Encrypt individual files with self-contained metadata. The encrypted file can be shared independently; the recipient only needs the same exe and the password.
- **Folder Hiding** — Optionally hides the encrypted directory using a Windows CLSID rename trick, making it invisible in File Explorer.
- **Drag & Drop** — Drag a file onto the window to instantly switch to single-file mode.
- **No Installation** — Compiles to a single `.exe` (~4 MB). No runtime dependencies.

## Screenshots

| Directory Mode | Single File Mode |
|:-:|:-:|
| ![directory](docs/directory.png) | ![single](docs/single.png) |

## Getting Started

### Download

Grab the latest `vault.exe` from [Releases](../../releases).

### Build from Source

```bash
cargo build --release
```

Output: `target/release/vault.exe`

Requires Rust 1.70+ and Windows.

## Usage

### Directory Encryption

1. Copy `vault.exe` into the target folder
2. Double-click to run
3. The app auto-detects unencrypted content and shows the encryption UI
4. Set a password, optionally check "Hide folder after encryption"
5. Click **Encrypt**
6. All files and subdirectories are encrypted in-place. You can take the exe with you — the folder now contains only garbled filenames and unreadable content.

### Directory Decryption

1. Put `vault.exe` back into the encrypted folder
2. Double-click to run
3. The app detects encrypted content and shows the decryption UI
4. Enter the password, click **Decrypt**
5. Everything is restored — files, names, directory structure, and timestamps.

### Single File Encryption / Decryption

1. Run `vault.exe` (from anywhere)
2. Switch to the **Single File** tab
3. Pick a file (or drag one in), set a password, click **Encrypt** / **Decrypt**

## Encryption Details

### Overview

| Component | Algorithm |
|---|---|
| **Content encryption** | AES-256-CTR (32-bit big-endian counter) |
| **Key derivation** | PBKDF2-HMAC-SHA256, 100,000 iterations |
| **Salt** | 16 bytes, CSPRNG per file |
| **Nonce / IV** | 16 bytes (128-bit), CSPRNG per file |
| **Metadata integrity** | CRC32 checksum |
| **Filename encryption** | AES-256-CTR with deterministic salt |

### Content Encryption

Each file is encrypted with **AES-256-CTR** using a unique key derived from the user's password.

```
password + salt (16 B, random) ──► PBKDF2-HMAC-SHA256 (100k rounds) ──► 256-bit key
key + nonce (16 B, random) ──► AES-256-CTR ──► ciphertext
```

**Partial encryption for large files (> 128 KiB):** only the first 64 KiB and last 64 KiB are encrypted. The middle is left untouched, giving near-instant processing for large files. Small files (<= 128 KiB) are fully encrypted.

### Metadata

Each encrypted file has a metadata block appended to the end:

```
┌─────────────────────────────────────────────────┐
│ Magic        "VALT" (4 bytes)                   │
│ Salt         (16 bytes, plaintext)              │
│ Nonce        (16 bytes, plaintext)              │
│ Meta Nonce   (16 bytes, plaintext)              │
│ Encrypted Payload:                              │
│   ├─ Original filename   (u16 len + UTF-8)     │
│   ├─ Original file size  (u64 LE)              │
│   ├─ Original mtime      (i64 LE, Unix secs)   │
│   └─ CRC32 checksum      (u32 LE)              │
│ Total length             (u32 LE, at EOF)       │
└─────────────────────────────────────────────────┘
```

The payload is encrypted with a **separate nonce** (`meta_nonce`) so metadata and content keystreams never overlap.

### Filename Encryption

File and directory names are encrypted deterministically (same password + name = same ciphertext) to allow directory-level operations without a name lookup table:

```
password + fixed salt ──► PBKDF2 ──► key
key + zero nonce ──► AES-256-CTR(name) ──► hex-encoded + ".dat"
```

### Security Notes

- **CTR mode is stream-only** — provides confidentiality but not authentication. A CRC32 checksum guards against accidental corruption and wrong-password detection, but is not a cryptographic MAC.
- **Partial encryption** leaks the middle portion of large files (> 128 KiB). This is a deliberate speed/size trade-off.
- **Deterministic name encryption** means identical filenames produce identical ciphertext, leaking name equality.
- **PBKDF2 at 100k iterations** — reasonable, but memory-hard KDFs (Argon2) would offer stronger resistance against GPU/ASIC attacks.

## Architecture

```
src/
├── main.rs          # Entry point, window setup, font loading
├── app.rs           # GUI (egui), mode detection, user interaction
├── crypto.rs        # AES-256-CTR, PBKDF2 key derivation
├── file_ops.rs      # File encrypt/decrypt (partial or full)
├── dir_ops.rs       # Recursive directory encrypt/decrypt
├── name_encrypt.rs  # Deterministic filename/dirname encryption
├── metadata.rs      # Metadata struct, serialization, detection
├── folder_hide.rs   # Windows CLSID-based folder hiding
├── validate.rs      # Pre-encryption validation
└── error.rs         # Error types
```

## Dependencies

| Crate | Purpose |
|---|---|
| `aes` + `ctr` | AES-256-CTR cipher |
| `pbkdf2` + `sha2` | PBKDF2-HMAC-SHA256 key derivation |
| `rand` | CSPRNG for salts and nonces |
| `crc32fast` | CRC32 integrity checksum |
| `hex` | Hex encoding for encrypted filenames |
| `walkdir` | Recursive directory traversal |
| `filetime` | Preserve file modification timestamps |
| `eframe` + `egui` | Cross-platform GUI framework |
| `rfd` | Native file dialogs |

## License

MIT
