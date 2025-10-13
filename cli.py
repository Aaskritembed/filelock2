import os
import sys
import json
import secrets
import shutil
import subprocess
import argparse
from datetime import datetime
from typing import List, Tuple, Dict, Any

from shamir import split_secret, combine_shares
from crypto import encrypt_bytes, decrypt_bytes
from archive import make_tar_bytes, extract_tar_bytes_to
from email_utils import send_email, generate_password_protected_pdf
from config import load_config, audit_log, get_current_user
from constants import KEY_SIZE

# --------------------------
# CLI Commands
# --------------------------
def cmd_init(args: argparse.Namespace) -> None:
    """Initialize encrypted archive and distribute shares"""
    cfg = load_config()
    recipients = cfg["recipients"]
    n = cfg.get("total_shares", len(recipients))
    k = cfg.get("quorum", max(1, (n + 1) // 2))  # Default to majority, but at least 1

    # Validate parameters
    if n != len(recipients):
        print(f"Warning: total_shares ({n}) doesn't match recipients count ({len(recipients)})")
        n = len(recipients)

    if k > n:
        print(f"Error: quorum ({k}) cannot exceed total_shares ({n})")
        sys.exit(1)

    enc_path = cfg.get("enc_path", "/var/secure-sss/secure_data.enc")
    shares_dir = cfg.get("shares_dir", "/var/secure-sss/shares")

    # Ensure directories exist
    os.makedirs(os.path.dirname(enc_path), exist_ok=True)
    os.makedirs(shares_dir, exist_ok=True)

    # Create archive
    print(f"Creating encrypted archive of: {args.folder}")
    try:
        tar_bytes = make_tar_bytes(args.folder)
    except Exception as e:
        print(f"Error creating archive: {e}")
        sys.exit(1)

    # Generate secret and encrypt
    secret = secrets.token_bytes(KEY_SIZE)
    encobj = encrypt_bytes(tar_bytes, secret)

    # Write encrypted archive atomically
    enc_path_tmp = enc_path + ".tmp"
    with open(enc_path_tmp, "w") as f:
        json.dump(encobj, f, indent=2)
    os.replace(enc_path_tmp, enc_path)

    # Split secret into shares
    shares = split_secret(secret, k, n)

    # Create round directory
    timestamp = int(datetime.utcnow().timestamp())
    round_dir = os.path.join(shares_dir, f"round_{timestamp}")
    os.makedirs(round_dir, exist_ok=True)

    # Save shares to files
    for i, share in enumerate(shares, start=1):
        share_file = os.path.join(round_dir, f"share_{i}.txt")
        with open(share_file, "w") as f:
            f.write(share + "\n")
        os.chmod(share_file, 0o600)  # Restrict permissions

    # Email shares
    smtp_cfg = cfg.get("smtp", {})
    recipients_names = cfg["recipients_names"]
    email_success = True
    if smtp_cfg and smtp_cfg.get("host"):
        for i, recipient in enumerate(recipients):
            share_text = shares[i]
            recipient_name = recipients_names[i]
            # Generate password: first 4 letters of email + first 4 letters of name
            email_prefix = recipient.split('@')[0][:4]
            name_prefix = recipient_name.replace(' ', '')[:4]
            password = email_prefix + name_prefix
            # Generate password-protected PDF
            pdf_bytes = generate_password_protected_pdf(share_text, password)
            subject = f"Secure Archive Share #{i+1}/{n}"
            body = (f"Your share for the secure archive (part {i+1} of {n}).\n\n"
                   f"Threshold: {k} shares required to unlock.\n"
                   f"Password for PDF: {password}\n"
                   f"DO NOT forward this email or share this with anyone.\n"
                   f"Keep this secret and secure.\n")

            try:
                send_email(smtp_cfg, recipient, subject, body,
                          attachment_bytes=pdf_bytes,
                          attachment_name=f"share_{i+1}.pdf")
                print(f"✓ Sent share {i+1} to {recipient}")
            except Exception as e:
                email_success = False
                print(f"✗ Failed to email share to {recipient}: {e}")
                print(f"  Share {i+1} (save this securely):\n  {share_text}\n")
    else:
        print("No SMTP config - shares saved to files only")
        email_success = False

    # Write metadata
    metadata = {
        "created_at": datetime.utcnow().isoformat() + "Z",
        "created_by": get_current_user(),
        "enc_path": enc_path,
        "round": round_dir,
        "quorum": k,
        "total": n,
        "version": "2"
    }
    with open(os.path.join(round_dir, "meta.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    # Delete share files if emails sent successfully
    if email_success:
        for i in range(1, n+1):
            share_file = os.path.join(round_dir, f"share_{i}.txt")
            try:
                os.remove(share_file)
                print(f"Deleted local share file: share_{i}.txt")
            except OSError:
                pass  # Ignore if file not found

    # Delete source folder after successful init
    try:
        shutil.rmtree(args.folder)
        print(f"Deleted source folder after init: {args.folder}")
    except Exception as e:
        print(f"Warning: Failed to delete source folder {args.folder}: {e}")

    audit_log(cfg, f"INIT by {get_current_user()} folder={args.folder} round={round_dir}")

    print(f"\n✓ Initialization complete")
    print(f"  Encrypted archive: {enc_path}")
    print(f"  Shares directory: {round_dir}")
    print(f"  Quorum: {k} of {n} shares required")
    print(f"\n⚠ IMPORTANT: Keep secure backups of the encrypted archive!")

def cmd_unlock(args: argparse.Namespace) -> None:
    """Unlock archive using shares, access folder, then optionally rotate"""
    cfg = load_config()
    enc_path = cfg.get("enc_path", "/var/secure-sss/secure_data.enc")
    k = cfg.get("quorum", 3)

    if not os.path.exists(enc_path):
        print(f"Error: Encrypted archive not found at {enc_path}")
        sys.exit(1)

    # Collect shares by Gmail
    recipients = cfg["recipients"]
    if len(recipients) != 5:
        print("Error: Exactly 5 recipients required")
        sys.exit(1)
    if k != 3:
        print("Error: Quorum must be 3")
        sys.exit(1)

    print("Available Gmail IDs: " + ", ".join(recipients))
    print("Enter Gmail ID and secret key. Type 'pass' to skip a Gmail. Need 3 shares.")
    shares = []
    used_gmails = set()
    while len(shares) < k:
        gmail = input(f"Enter Gmail ID ({len(shares)+1}/{k} collected): ").strip()
        if gmail in used_gmails:
            print("Gmail already used.")
            continue
        if gmail not in recipients:
            print("Invalid Gmail ID.")
            continue
        secret_key = input(f"Enter secret key for {gmail} (or 'pass' to skip): ").strip()
        if secret_key.lower() == 'pass':
            continue
        if not secret_key:
            print("Empty secret key - try again")
            continue
        shares.append(secret_key)
        used_gmails.add(gmail)

    # Reconstruct secret
    try:
        secret = combine_shares(shares)
    except Exception as e:
        print(f"✗ Failed to reconstruct secret: {e}")
        audit_log(cfg, f"UNLOCK_FAILED by {get_current_user()} reason=combine_error")
        sys.exit(1)

    # Load and decrypt archive
    try:
        with open(enc_path, "r") as f:
            encobj = json.load(f)

        plaintext = decrypt_bytes(encobj, secret)
    except Exception as e:
        print(f"✗ Decryption failed: {e}")
        print("  Wrong shares or corrupted archive")
        audit_log(cfg, f"UNLOCK_FAILED by {get_current_user()} reason=decrypt_error")
        sys.exit(1)

    # Extract archive
    unlock_dir = args.unlock_dir or "/tmp/secure_unlocked"
    try:
        extract_tar_bytes_to(plaintext, unlock_dir)
        print(f"✓ Archive decrypted to: {unlock_dir}")
        audit_log(cfg, f"UNLOCK_SUCCESS by {get_current_user()} out={unlock_dir}")
    except Exception as e:
        print(f"✗ Extraction failed: {e}")
        sys.exit(1)

    print(f"You can now access and modify the folder: {unlock_dir}")

    # Log file changes
    def get_file_info(root):
        info = {}
        for dirpath, dirnames, filenames in os.walk(root):
            for f in filenames:
                path = os.path.join(dirpath, f)
                try:
                    stat = os.stat(path)
                    info[path] = (stat.st_size, stat.st_mtime)
                except OSError:
                    pass  # Ignore errors
        return info

    before_info = get_file_info(unlock_dir)

    # Start bash with script to log session
    logfile = os.path.join('/home/vsure/Downloads/filelock-main/session_folder', f'session_{int(datetime.utcnow().timestamp())}.log')
    subprocess.call(['script', '-f', '-a', logfile, 'bash'])
    os.chmod(logfile, 0o444)
    # Make immutable to prevent deletion
    subprocess.call(['chattr', '+i', logfile])

    # Log changes
    after_info = get_file_info(unlock_dir)
    changes = []
    all_paths = set(before_info) | set(after_info)
    for p in all_paths:
        if p not in before_info:
            changes.append(f"ADDED {os.path.relpath(p, unlock_dir)}")
        elif p not in after_info:
            changes.append(f"DELETED {os.path.relpath(p, unlock_dir)}")
        elif before_info[p] != after_info[p]:
            changes.append(f"MODIFIED {os.path.relpath(p, unlock_dir)}")

    audit_log(cfg, f"SHELL_SESSION by {get_current_user()} dir={unlock_dir} log={logfile} changes={'; '.join(changes) if changes else 'none'}")

    # Ask about rotation
    print("\n" + "="*60)
    response = input("Type 'rotate' to re-encrypt with new shares (or anything else to skip): ").strip().lower()

    if response != "rotate":
        print("Rotation skipped. Archive remains unlocked.")
        print(f"⚠ Remember to securely delete: {unlock_dir}")
        audit_log(cfg, f"UNLOCK_NO_ROTATE by {get_current_user()}")
        return

    # Perform rotation
    print("\n🔄 Rotating encryption key...")

    try:
        # Generate new secret
        new_secret = secrets.token_bytes(KEY_SIZE)

        # Re-archive and encrypt
        new_tar_bytes = make_tar_bytes(unlock_dir)
        new_encobj = encrypt_bytes(new_tar_bytes, new_secret)

        # Atomic write
        enc_path_tmp = enc_path + ".tmp"
        with open(enc_path_tmp, "w") as f:
            json.dump(new_encobj, f, indent=2)
        os.replace(enc_path_tmp, enc_path)

        # Generate new shares
        recipients = cfg["recipients"]
        n = cfg.get("total_shares", len(recipients))
        new_shares = split_secret(new_secret, k, n)

        # Create new round
        timestamp = int(datetime.utcnow().timestamp())
        shares_dir = cfg.get("shares_dir", "/var/secure-sss/shares")
        round_dir = os.path.join(shares_dir, f"round_{timestamp}")
        os.makedirs(round_dir, exist_ok=True)

        # Save shares
        for i, share in enumerate(new_shares, start=1):
            share_file = os.path.join(round_dir, f"share_{i}.txt")
            with open(share_file, "w") as f:
                f.write(share + "\n")
            os.chmod(share_file, 0o600)

        # Email new shares
        smtp_cfg = cfg.get("smtp", {})
        recipients_names = cfg["recipients_names"]
        rotate_email_success = True
        if smtp_cfg and smtp_cfg.get("host"):
            for i, recipient in enumerate(recipients):
                share_text = new_shares[i]
                recipient_name = recipients_names[i]
                # Generate password: first 4 letters of email + first 4 letters of name
                email_prefix = recipient.split('@')[0][:4]
                name_prefix = recipient_name.replace(' ', '')[:4]
                password = email_prefix + name_prefix
                # Generate password-protected PDF
                pdf_bytes = generate_password_protected_pdf(share_text, password)
                subject = f"NEW Secure Archive Share #{i+1}/{n}"
                body = (f"Your NEW share for the secure archive (part {i+1} of {n}).\n\n"
                       f"⚠ OLD SHARES ARE NOW INVALID ⚠\n\n"
                       f"Threshold: {k} shares required to unlock.\n"
                       f"Password for PDF: {password}\n"
                       f"DO NOT forward or share this.\n")

                try:
                    send_email(smtp_cfg, recipient, subject, body,
                              attachment_bytes=pdf_bytes,
                              attachment_name=f"share_{i+1}.pdf")
                    print(f"✓ Sent new share {i+1} to {recipient}")
                except Exception as e:
                    rotate_email_success = False
                    print(f"✗ Failed to email share to {recipient}: {e}")
                    print(f"  Share {i+1}:\n  {share_text}\n")

        # Write metadata
        metadata = {
            "rotated_at": datetime.utcnow().isoformat() + "Z",
            "rotated_by": get_current_user(),
            "enc_path": enc_path,
            "round": round_dir,
            "quorum": k,
            "total": n,
            "version": "2"
        }
        with open(os.path.join(round_dir, "meta.json"), "w") as f:
            json.dump(metadata, f, indent=2)

        # Delete new share files if emails sent successfully
        if rotate_email_success:
            for i in range(1, n+1):
                share_file = os.path.join(round_dir, f"share_{i}.txt")
                try:
                    os.remove(share_file)
                    print(f"Deleted local new share file: share_{i}.txt")
                except OSError:
                    pass  # Ignore if file not found

        audit_log(cfg, f"ROTATE by {get_current_user()} round={round_dir}")

        print(f"\n✓ Rotation complete")
        print(f"  New shares: {round_dir}")
        print(f"  ⚠ Old shares are now invalid")

        # Delete unlocked directory after successful rotation
        try:
            shutil.rmtree(unlock_dir)
            print(f"Deleted unlocked directory after rotation: {unlock_dir}")
        except Exception as e:
            print(f"Warning: Failed to delete unlocked directory {unlock_dir}: {e}")

    except Exception as e:
        print(f"✗ Rotation failed: {e}")
        audit_log(cfg, f"ROTATE_FAILED by {get_current_user()} error={e}")
        sys.exit(1)
    finally:
        # Securely clear sensitive data
        secret = None
        new_secret = None

def main():
    parser = argparse.ArgumentParser(
        description="Secure Secret Sharing CLI - Encrypt archives with distributed shares",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="cmd", help="Available commands")
    
    # Init command
    parser_init = subparsers.add_parser("init",
                                        help="Initialize encrypted archive and distribute shares")
    parser_init.add_argument("folder", help="Folder to archive and encrypt")
    
    # Unlock command
    parser_unlock = subparsers.add_parser("unlock",
                                          help="Unlock archive using shares, access folder, then optionally rotate")
    parser_unlock.add_argument("--unlock-dir",
                              help="Directory to extract decrypted archive (default: /tmp/secure_unlocked)")
    
    args = parser.parse_args()
    
    if not args.cmd:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.cmd == "init":
            cmd_init(args)
        elif args.cmd == "unlock":
            cmd_unlock(args)
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
