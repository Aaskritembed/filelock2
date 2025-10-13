import smtplib
from typing import Dict, Any
from email.message import EmailMessage
from fpdf import FPDF
from pypdf import PdfWriter, PdfReader
from io import BytesIO

# --------------------------
# Email functionality
# --------------------------
def generate_password_protected_pdf(text: str, password: str) -> bytes:
    """Generate a password-protected PDF containing the given text"""
    # Create PDF with text
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, text)

    # Get PDF bytes
    pdf_bytes = pdf.output(dest='S').encode('latin1')

    # Encrypt the PDF
    reader = PdfReader(BytesIO(pdf_bytes))
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    writer.encrypt(password)

    encrypted_pdf = BytesIO()
    writer.write(encrypted_pdf)
    return encrypted_pdf.getvalue()

def send_email(smtp_cfg: Dict[str, Any], to_addr: str, subject: str,
               body: str, attachment_bytes: bytes = None, attachment_name: str = "share.pdf") -> None:
    """Send email with optional text attachment"""
    msg = EmailMessage()
    msg["From"] = smtp_cfg.get("from", smtp_cfg.get("username"))
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)

    if attachment_bytes:
        msg.add_attachment(attachment_bytes, maintype='application',
                          subtype='pdf', filename=attachment_name)
    
    host = smtp_cfg["host"]
    port = smtp_cfg.get("port", 587)
    username = smtp_cfg.get("username")
    password = smtp_cfg.get("password")
    use_starttls = smtp_cfg.get("starttls", True)
    
    server = smtplib.SMTP(host, port, timeout=30)
    try:
        server.ehlo()
        if use_starttls:
            server.starttls()
            server.ehlo()
        if username:
            server.login(username, password)
        server.send_message(msg)
    finally:
        server.quit()
