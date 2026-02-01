from flask import Flask, render_template, request, send_file, flash, redirect, url_for
import os, random, time, threading
from cryptography.fernet import Fernet
import smtplib
from email.message import EmailMessage
from datetime import datetime

app = Flask(__name__)
app.secret_key = "securefilesharingproject"

# ================= BREVO SMTP (ONLY THESE) =================
SMTP_HOST = os.getenv("SMTP_HOST")          # smtp-relay.brevo.com
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_LOGIN = os.getenv("SMTP_LOGIN")        # a0f45xxx@smtp-brevo.com
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD") # SMTP KEY
SENDER_EMAIL = os.getenv("SENDER_EMAIL")   # securefileshare123@gmail.com

# ================= FOLDERS =================
os.makedirs("encrypted_files", exist_ok=True)
os.makedirs("logs", exist_ok=True)

# ================= ENCRYPTION =================
KEY_FILE = "secret.key"
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, "wb") as f:
        f.write(Fernet.generate_key())

with open(KEY_FILE, "rb") as f:
    cipher = Fernet(f.read())

# ================= GLOBAL STATE =================
generated_otp = None
otp_created_time = None
receiver_email = None
wrong_attempts = 0
already_downloaded = False

OTP_VALID
