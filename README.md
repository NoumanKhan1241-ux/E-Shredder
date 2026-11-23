# E-Shredder – Secure File Erasure for Windows

**A Rust-based application designed to securely erase files from Windows NTFS file systems.**

E-Shredder aims to go beyond conventional file deletion by investigating NTFS internals, identifying file storage locations, and implementing secure data-erasure techniques.

Unlike ordinary deletion, which generally marks storage space as available for reuse, E-Shredder explores low-level Windows APIs and NTFS structures to provide a more secure approach to file removal.

---

## Project Overview

When a file is deleted through Windows File Explorer, its contents may remain on the storage device until the corresponding storage space is reused.

E-Shredder is being developed to address this limitation by exploring secure file-erasure techniques using Rust and Windows system APIs.

The application focuses on the Windows NTFS file system, particularly its Master File Table (MFT), file records, and Data Runs.

The primary objective is to understand how files are physically allocated on disk and how their contents can be securely erased before normal filesystem deletion.

## Planned Features

-  **Secure File Erasure:** Implement file-data overwriting before normal deletion.
-  **Rust Implementation:** Built using Rust for performance, memory safety, and systems-level access.
-  **NTFS Support:** Investigate and interact with Windows NTFS file systems.
-  **MFT Record Analysis:** Retrieve and examine Master File Table records.
-  **Data Run Extraction:** Identify file allocation extents and corresponding disk clusters.
-  **Windows API Integration:** Utilize Windows low-level APIs through the `windows-sys` crate.
-  **Data Verification:** Cross-check extracted Data Runs using disk inspection utilities.
-  **Windows Context Menu:** Planned integration for accessing secure erasure through File Explorer.

## Technology Stack

| Technology | Purpose |
|---|---|
| Rust | Core programming language |
| Cargo | Package management and build system |
| windows-sys | Low-level Windows API access |
| Windows API | File and volume operations |
| NTFS | Target file system |
| WinHex / Disk Editor | Disk-level inspection and verification |
| Visual Studio Code | Development environment |

## System Workflow

The planned E-Shredder workflow consists of the following stages:

1. **File Path Input:** Accept the target file path through command-line arguments.
2. **File Validation:** Check whether the specified file exists using Rust filesystem APIs.
3. **MFT Identification:** Retrieve the file's Master File Table record information.
4. **MFT Analysis:** Locate and examine the relevant NTFS file record.
5. **Data Run Extraction:** Identify the allocated data extents associated with the file.
6. **Data Verification:** Verify the extracted storage locations using a Disk Editor.
7. **Secure Erasure:** Implement the appropriate data-overwriting procedure.
8. **Deletion Finalization:** Perform normal filesystem deletion and verify the outcome.

## Proposed Project Structure

```text
e_shredder/
│
├── Cargo.toml
├── Cargo.lock
├── README.md
│
├── src/
│   ├── main.rs
│   ├── cli.rs
│   ├── file_handler.rs
│   ├── ntfs.rs
│   ├── mft.rs
│   ├── data_runs.rs
│   ├── shredder.rs
│   ├── verifier.rs
│   └── errors.rs
│
├── tests/
│   ├── file_tests.rs
│   ├── ntfs_tests.rs
│   └── verification_tests.rs
│
└── docs/
    ├── architecture.md
    └── testing.md
```

*Note: This represents the proposed architecture and may change during development.*

## Prerequisites

Before getting started, make sure you have:

- Windows 10 or Windows 11.
- Rust toolchain installed.
- Cargo package manager.
- Visual Studio Code or another Rust-compatible IDE.
- Administrator privileges for operations that require raw volume access.
- An NTFS-formatted test volume.

### Install Rust

Download and install Rust using the official website:

https://www.rust-lang.org/tools/install

Verify the installation:

```bash
rustc --version
cargo --version
```

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR-USERNAME/e_shredder.git
```

### 2. Navigate to the Project Directory

```bash
cd e_shredder
```

### 3. Build the Application

```bash
cargo build
```

### 4. Run the Application

```bash
cargo run
```

The command-line interface and available commands will be documented as their implementation is completed.

## Dependencies

The project is intended to use the following Rust crates:

```toml
[dependencies]
windows-sys = "0.61"
clap = { version = "4", features = ["derive"] }
anyhow = "1"
thiserror = "2"
log = "0.4"
env_logger = "0.11"
```

Dependency versions and required Windows API features may be adjusted during development.

## Testing and Verification

Testing is an important part of E-Shredder because incorrect disk operations can result in permanent data loss.

The testing process will include:

- File existence and metadata validation.
- NTFS volume identification.
- MFT record inspection.
- Data Run extraction.
- Cluster location verification.
- File fragmentation testing.
- Secure-erasure verification.
- Error handling and permission testing.

Disk inspection tools such as WinHex will be used to cross-check extracted Data Runs before destructive operations are attempted.

## Security Considerations

E-Shredder is designed with secure data handling in mind.

Important limitations include:

- Overwriting logical file locations does not guarantee physical erasure on SSDs because of wear levelling and remapped storage blocks.
- NTFS metadata, journals, backups, and Volume Shadow Copies may retain information.
- Files with multiple hard links or alternate data streams require additional handling.
- Incorrect low-level disk operations can damage filesystem structures and unrelated files.

Testing should be performed in an isolated virtual machine using a disposable NTFS test disk.

**E-Shredder will not claim guaranteed permanent physical erasure unless the selected storage device and sanitization method support that guarantee.**

## Project Objectives

1. Explore Windows NTFS filesystem architecture.
2. Understand Master File Table records and Data Runs.
3. Implement low-level Windows API operations using Rust.
4. Develop a secure file-erasure mechanism.
5. Verify file storage locations before destructive operations.
6. Explore Windows Explorer context-menu integration.

## Future Improvements

- Graphical User Interface (GUI).
- Windows Explorer right-click integration.
- Detailed erasure reports.
- Progress tracking and operation logs.
- Support for additional filesystem configurations.
- Storage-device-aware sanitization methods.

## Author

**Muhammad Nouman Khan**

Rust | Systems Programming | Windows Internals | Cybersecurity

## License

This project is intended for educational and research purposes. A license will be added once the project's distribution terms are finalized.

---

⭐ If you find this project interesting, consider following its development and exploring the implementation of secure file erasure in Rust.
