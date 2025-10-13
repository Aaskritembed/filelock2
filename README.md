# FileLocker - Secure Secret Sharing CLI

A command-line tool for securely encrypting archives and distributing decryption shares using Shamir's Secret Sharing over a prime field. This tool supports exactly 5 recipients with a threshold of 3 shares required to unlock, providing distributed trust.

## Features

- **Shamir's Secret Sharing**: Splits encryption keys into shares with configurable threshold.
- **AES-256-GCM Encryption**: Secure encryption with authenticated encryption.
- **Archive Management**: Creates and extracts tar.gz archives.
- **Email Distribution**: Optionally emails shares to recipients via SMTP.
- **Audit Logging**: Logs operations with timestamps.
- **Key Rotation**: Supports rotating encryption keys after unlocking.
- **Modular Design**: Refactored into separate modules for maintainability.

## Requirements

- Python 3.8+
- `cryptography` library: `pip install cryptography`
- `python-dotenv` library: `pip install python-dotenv`

## Installation

1. Clone or download the codebase.
2. Install dependencies: `pip install cryptography python-dotenv`
3. Create a `.env` file with your configuration (see Configuration below).

## Usage

### Initialize Encrypted Archive

Create an encrypted archive from a folder and distribute shares:

```bash
python filelocker.py init <folder_path>
```

- `<folder_path>`: Path to the folder to archive and encrypt.

This command:
- Archives the folder into a tar.gz.
- Generates a random encryption key.
- Encrypts the archive with AES-256-GCM.
- Splits the key into shares using Shamir's Secret Sharing.
- Saves shares to files and optionally emails them.

### Unlock Archive

Reconstruct the key from shares and decrypt the archive:

```bash
python filelocker.py unlock [--unlock-dir <output_dir>]
```

- `--unlock-dir`: Directory to extract decrypted archive (default: `/tmp/secure_unlocked`).

This command:
- Displays the list of recipient Gmail IDs.
- Prompts for a Gmail ID, then the secret key (share) for that Gmail, or "pass" to skip.
- Collects exactly 3 shares from different recipients.
- Reconstructs the encryption key.
- Decrypts and extracts the archive.
- Starts a bash shell in the extracted directory for access and modifications using Linux commands.
- Logs the bash session (commands and output) in real-time to 'session.log' in the extracted directory (read-only for all users).
- Audits file changes made during the session.
- After exiting the shell, prompts for optional key rotation and redistribution of new shares.

### Help

Display help:

```bash
python filelocker.py --help
```

## How It Works

### Initialization Process (`init` command)

1. **Archive Creation**: The specified folder is compressed into a tar.gz archive using `make_tar_bytes` from `archive.py`.

2. **Key Generation**: A random 32-byte encryption key is generated using `secrets.token_bytes`.

3. **Encryption**: The archive is encrypted using AES-256-GCM via `encrypt_bytes` in `crypto.py`. This produces a JSON object containing the encrypted data, nonce, salt, and version info.

4. **Secret Splitting**: The encryption key is split into `n` shares using Shamir's Secret Sharing (`split_secret` in `shamir.py`), where `k` shares are required to reconstruct the key.

5. **Share Distribution**: Shares are saved to timestamped files in the shares directory. If SMTP is configured, each recipient receives only their assigned share via email using `send_email` from `email_utils.py`. No single recipient has access to the complete encryption key.

6. **Metadata and Logging**: Metadata about the operation is saved, and the action is logged via `audit_log` in `config.py`.

### Unlocking Process (`unlock` command)

1. **Share Collection**: The tool displays the list of 5 recipient Gmail IDs. The user is prompted to enter a Gmail ID, then provide the secret key (share) associated with it, or type "pass" to skip that recipient. This continues until exactly 3 shares are collected from different recipients.

2. **Key Reconstruction**: Shares are combined using Lagrange interpolation (`combine_shares` in `shamir.py`) to recover the original encryption key.

3. **Decryption**: The encrypted archive is decrypted using AES-256-GCM (`decrypt_bytes` in `crypto.py`).

4. **Extraction**: The decrypted tar.gz data is extracted to the specified output directory using `extract_tar_bytes_to` from `archive.py`.

5. **Access and Modification**: A bash shell is started in the extracted directory, allowing the user to access and modify files using Linux commands. All commands and output are logged in real-time to 'session.log' in the directory (with read-only permissions for all users), and file changes are audited.

6. **Optional Rotation**: After exiting the shell, the user is prompted to rotate the key:
   - A new random key is generated.
   - The unlocked data is re-archived and re-encrypted.
   - New shares are created and distributed via email, invalidating old shares.
   - Local share files are deleted after successful email sending.
   - Metadata and logs are updated.

All operations are audited, and sensitive data is cleared from memory after use.

## Configuration

The tool loads all configuration from environment variables. Create a `.env` file in the project root with the following settings:

```env
# Required: Recipients for share distribution (exactly 5 Gmail addresses)
RECIPIENTS=recipient1@gmail.com,recipient2@gmail.com,recipient3@gmail.com,recipient4@gmail.com,recipient5@gmail.com

# Optional: SMTP settings (supports any email provider, e.g., Gmail, Outlook, etc.)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
SMTP_STARTTLS=true

# Fixed: Share parameters (5 shares, 3 required)
TOTAL_SHARES=5
QUORUM=3

# Optional: File paths (supports ~ for home directory)
ENC_PATH=~/secure-sss/secure_data.enc
SHARES_DIR=~/secure-sss/shares
AUDIT_LOG=~/secure-sss/audit.log
```

- `RECIPIENTS`: Comma-separated list of exactly 5 Gmail addresses for share distribution (required).
- `TOTAL_SHARES`: Fixed to 5 shares.
- `QUORUM`: Fixed to 3 shares required to unlock.
- `ENC_PATH`: Path to store encrypted archive (default: `~/secure-sss/secure_data.enc`).
- `SHARES_DIR`: Directory for share files (default: `~/secure-sss/shares`).
- `AUDIT_LOG`: Path for audit log (default: `~/secure-sss/audit.log`).
- SMTP settings: Optional; if not set, shares are saved to files only. Supports any SMTP provider.

## Project Structure

The codebase is modular for easy maintenance:

- `filelocker.py`: Entry point script that imports and runs the main function from `cli.py`.
- `cli.py`: Contains the command-line interface using argparse, with `cmd_init` for initializing encrypted archives and distributing shares, and `cmd_unlock` for reconstructing keys and decrypting archives. Handles user input, validation, and orchestration of other modules.
- `shamir.py`: Implements Shamir's Secret Sharing over a prime field (2^521-1). `split_secret` generates shares by evaluating a random polynomial at distinct points. `combine_shares` reconstructs the secret using Lagrange interpolation.
- `crypto.py`: Handles encryption and decryption using AES-256-GCM with PBKDF2 key derivation. Supports versioning for backward compatibility (v1 uses SHA256, v2 uses PBKDF2 with salt).
- `archive.py`: Manages tar.gz archive creation (`make_tar_bytes`) and extraction (`extract_tar_bytes_to`) using temporary files for efficient handling.
- `email_utils.py`: Provides SMTP-based email sending with optional text attachments, supporting various providers via configurable settings.
- `config.py`: Loads configuration from environment variables (via .env file), handles audit logging to files, and retrieves the current user for metadata.
- `constants.py`: Defines constants like the prime for Shamir, key size (32 bytes for AES-256), nonce size (12 bytes for GCM), and PBKDF2 iterations (600,000).

## How to Use the Codebase

### For Users

1. Set up the `.env` file with your settings.
2. Run `python filelocker.py init <folder>` to encrypt and share.
3. Distribute shares securely.
4. Use `python filelocker.py unlock` when needed, providing shares interactively.

### For Developers

- **Modifying Functionality**: Edit the relevant module (e.g., `crypto.py` for encryption changes).
- **Adding Features**: Add new functions to appropriate modules and update `cli.py` for new commands.
- **Testing**: Import modules individually for unit testing, e.g., `from shamir import split_secret, combine_shares`.
- **Dependencies**: All modules import only standard library and `cryptography`. Add new dependencies to requirements if needed.
- **Security**: Handle sensitive data carefully; avoid logging secrets.

## Security Notes

- Shares must be kept secure; compromise of 3 or more shares allows decryption.
- Use strong SMTP passwords and secure email.
- Regularly rotate keys after unlocking.
- Local share files are automatically deleted after successful email distribution to minimize exposure.
- Audit logs help track usage.