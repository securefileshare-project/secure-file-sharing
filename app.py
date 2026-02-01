from flask import Flask, render_template, request, send_file, flash, redirect, url_for
import os
import random
import time
import threading
from cryptography.fernet import Fernet
import smtplib
from email.message import EmailMessage
from datetime import datetime

app = Flask(__name__)
app.secret_key = "securefilesharingproject"

# ================= EMAIL (BREVO SMTP) =================
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_LOGIN = os.getenv("SMTP_LOGIN")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")

# ================= FOLDERS =================
os.makedirs("encrypted_files", exist_ok=True)
os.makedirs("logs", exist_ok=True)

# ================= ENCRYPTION =================
KEY_FILE = "secret.key"
if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
else:
    with open(KEY_FILE, "rb") as f:
        key = f.read()

cipher = Fernet(key)

# ================= GLOBAL STATE =================
generated_otp = None
otp_created_time = None
OTP_VALIDITY = 180          # 3 minutes
wrong_attempts = 0
MAX_ATTEMPTS = 3
otp_blocked = False
receiver_email = None
already_downloaded = False

# ================= LOG =================
def write_log(email, ip, status):
    with open("logs/download_log.txt", "a") as log:
        t = datetime.now().strftime("%d-%m-%Y %I:%M %p")
        log.write(f"{t} | {email} | {ip} | {status}\n")

# ================= SEND OTP (BREVO) =================
from email.message import EmailMessage
import smtplib
import os

def send_otp_email(receiver, otp):
    try:
        msg = EmailMessage()
        msg["Subject"] = "Secure File Sharing - OTP"
        msg["From"] = os.environ.get("SENDER_EMAIL")
        msg["To"] = receiver
        msg.set_content(f"Your OTP is: {otp}")

        smtp_server = os.environ.get("SMTP_SENDER")   # smtp-relay.brevo.com
        smtp_port = int(os.environ.get("SMTP_PORT")) # 587
        smtp_login = os.environ.get("SMTP_LOGIN")
        smtp_password = os.environ.get("SMTP_PASSWORD")

        # 👇 IMPORTANT: create SMTP INSIDE function
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(smtp_login, smtp_password)
            server.send_message(msg)

        print("OTP mail sent successfully")
        return True

    except Exception as e:
        print("OTP Mail sending failed:", e)
        return False

# ================= UPLOAD (SENDER) =================
@app.route("/", methods=["GET", "POST"])
def upload_file():
    global generated_otp, otp_created_time, wrong_attempts, otp_blocked
    global receiver_email, already_downloaded

    if request.method == "POST":
        file = request.files.get("file")
        receiver_email = request.form.get("email")

        if not file or file.filename == "":
            flash("Please choose a file", "danger")
            return redirect(url_for("upload_file"))

        # Encrypt & save
        data = file.read()
        enc = cipher.encrypt(data)
        enc_path = os.path.join("encrypted_files", file.filename)
        with open(enc_path, "wb") as f:
            f.write(enc)

        # OTP setup
        generated_otp = random.randint(100000, 999999)
        otp_created_time = time.time()
        wrong_attempts = 0
        otp_blocked = False
        already_downloaded = False

        verify_link = request.url_root + "verify"
        ok = send_otp_email(receiver_email, generated_otp)

        if not ok:
            flash("OTP email failed. Try again.", "danger")
            return redirect(url_for("upload_file"))

        flash("File uploaded. OTP sent to receiver email.", "success")
        return render_template("sent.html")  # simple info page

    return render_template("upload.html")

# ================= VERIFY (RECEIVER) =================
@app.route("/verify", methods=["GET", "POST"])
def verify_otp():
    global wrong_attempts, otp_blocked

    if request.method == "POST":
        user_otp = request.form.get("otp")

        if otp_blocked:
            write_log(receiver_email, request.remote_addr, "BLOCKED")
            flash("OTP blocked. Upload again.", "danger")
            return redirect(url_for("upload_file"))

        if time.time() - otp_created_time > OTP_VALIDITY:
            otp_blocked = True
            write_log(receiver_email, request.remote_addr, "OTP EXPIRED")
            flash("OTP expired.", "danger")
            return redirect(url_for("upload_file"))

        if str(user_otp) == str(generated_otp):
            write_log(receiver_email, request.remote_addr, "OTP VERIFIED")

            files = os.listdir("encrypted_files")
            name = files[-1]
            size = round(os.path.getsize(os.path.join("encrypted_files", name)) / 1024, 2)

            return render_template(
                "download_ready.html",
                filename=name,
                size=size
            )

        wrong_attempts += 1
        write_log(receiver_email, request.remote_addr, "WRONG OTP")

        if wrong_attempts >= MAX_ATTEMPTS:
            otp_blocked = True
            write_log(receiver_email, request.remote_addr, "BLOCKED – TOO MANY ATTEMPTS")
            flash("Too many wrong attempts.", "danger")
        else:
            flash("Invalid OTP.", "danger")

    return render_template("otp.html")

# ================= CLEANUP =================
def delayed_cleanup(paths):
    time.sleep(3)
    for p in paths:
        try:
            if os.path.exists(p):
                os.remove(p)
        except:
            pass

# ================= DOWNLOAD (RECEIVER) =================
@app.route("/download")
def download_file():
    global already_downloaded

    if already_downloaded:
        write_log(receiver_email, request.remote_addr, "SECOND DOWNLOAD BLOCKED")
        flash("File already downloaded.", "danger")
        return redirect(url_for("upload_file"))

    files = os.listdir("encrypted_files")
    if not files:
        flash("No file found.", "danger")
        return redirect(url_for("upload_file"))

    enc_name = files[-1]
    enc_path = os.path.join("encrypted_files", enc_name)

    with open(enc_path, "rb") as f:
        enc_data = f.read()

    dec = cipher.decrypt(enc_data)
    dec_path = os.path.join("encrypted_files", "decrypted_" + enc_name)

    with open(dec_path, "wb") as f:
        f.write(dec)

    already_downloaded = True
    write_log(receiver_email, request.remote_addr, "SUCCESS")

    threading.Thread(
        target=delayed_cleanup,
        args=([enc_path, dec_path],),
        daemon=True
    ).start()

    return send_file(dec_path, as_attachment=True)

# ================= ADMIN LOGS =================
@app.route("/admin/logs")
def admin_logs():
    logs = []
    p = "logs/download_log.txt"
    if os.path.exists(p):
        with open(p) as f:
            for line in f:
                d, e, i, s = [x.strip() for x in line.split("|")]
                logs.append({"date": d, "email": e, "ip": i, "status": s})
    return render_template("logs.html", logs=logs)

# ================= RUN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)



