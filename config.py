import os
import json
import sys
import getpass
from datetime import datetime
from typing import Dict, Any

# Load environment variables from .env file if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# --------------------------
# Configuration and logging
# --------------------------
def load_config() -> Dict[str, Any]:
    """Load configuration from environment variables"""
    cfg = {}

    # Load recipients from environment
    recipients_str = os.environ.get('RECIPIENTS')
    if recipients_str:
        cfg["recipients"] = [r.strip() for r in recipients_str.split(',')]
    else:
        raise ValueError("RECIPIENTS env var is required")

    # Load recipients names from environment
    recipients_names_str = os.environ.get('RECIPIENTS_NAMES')
    if recipients_names_str:
        cfg["recipients_names"] = [n.strip() for n in recipients_names_str.split(',')]
    else:
        raise ValueError("RECIPIENTS_NAMES env var is required")

    # Validate required fields
    if not cfg["recipients"]:
        raise ValueError("RECIPIENTS env var must contain at least one recipient")
    if not cfg["recipients_names"]:
        raise ValueError("RECIPIENTS_NAMES env var must contain at least one name")
    if len(cfg["recipients"]) != len(cfg["recipients_names"]):
        raise ValueError("RECIPIENTS and RECIPIENTS_NAMES must have the same number of entries")

    # Load SMTP settings from environment variables
    cfg['smtp'] = {}
    smtp = cfg['smtp']
    smtp['host'] = os.environ.get('SMTP_HOST', '')
    smtp['port'] = int(os.environ.get('SMTP_PORT', '587'))
    smtp['username'] = os.environ.get('SMTP_USERNAME')
    smtp['password'] = os.environ.get('SMTP_PASSWORD')
    smtp['starttls'] = os.environ.get('SMTP_STARTTLS', 'true').lower() == 'true'

    # Load other config from environment
    secure_dir = os.path.join(os.path.expanduser('~'), 'secure-sss')
    cfg['audit_log'] = os.path.expanduser(os.environ.get('AUDIT_LOG', os.path.join(secure_dir, 'audit.log')))
    cfg['enc_path'] = os.path.expanduser(os.environ.get('ENC_PATH', os.path.join(secure_dir, 'secure_data.enc')))
    cfg['shares_dir'] = os.path.expanduser(os.environ.get('SHARES_DIR', os.path.join(secure_dir, 'shares')))

    # Optional: total_shares and quorum
    total_shares = os.environ.get('TOTAL_SHARES')
    if total_shares:
        cfg['total_shares'] = int(total_shares)

    quorum = os.environ.get('QUORUM')
    if quorum:
        cfg['quorum'] = int(quorum)

    return cfg

def audit_log(cfg: Dict[str, Any], message: str) -> None:
    """Write audit log entry with timestamp"""
    log_path = cfg.get("audit_log", "/var/secure-sss/audit.log")
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    try:
        # Ensure log directory exists
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        
        with open(log_path, "a") as f:
            f.write(f"{timestamp} {message}\n")
    except Exception as e:
        print(f"Warning: Failed to write audit log: {e}", file=sys.stderr)

def get_current_user() -> str:
    """Get current username safely"""
    try:
        return os.getlogin()
    except Exception:
        return getpass.getuser()
