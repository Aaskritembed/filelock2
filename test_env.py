import os
from dotenv import load_dotenv

load_dotenv()

print("SMTP_HOST:", os.environ.get('SMTP_HOST'))
print("RECIPIENTS:", os.environ.get('RECIPIENTS'))
