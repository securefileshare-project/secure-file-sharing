from flask import Flask, render_template, request, send_file, flash, redirect, url_for
import os
import random
import time
import threading
from cryptography.fernet import Fernet
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

app = Flask(__name__)
app.secret_key = "securefilesharingproject"

# ---------- ENV VARIABLES (FROM RAILWAY) ----------
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT"))
SMTP_LOGIN = os.getenv("SMTP_LOGIN")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_NAME = os.getenv("SENDER_NAME", "Secure File Share")

# ---------- FOLDERS ----------
os.makedirs("encrypted_files", exist_ok=True)
os.makedirs("logs", exist_ok=True)

# ---------- ENCRYPTION ----------
KEY_FILE = "secret.key"

if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
else:
    with open(KEY_FILE, "rb") as f:
        key = f.read()

cipher = Fernet(key)

# ---------- SEND OTP EMAIL (BREVO SMTP) ----------
def send_otp_email(receiver, otp):
    try:
        msg = EmailMessage()
        msg["Subject"] = "Secure File Sharing - OTP"
        msg["From"] = f"{SENDER_NAME} <{SENDER_EMAIL}>"
        msg["To"] = receiver
        msg.set_content(
            f"Your OTP is: {otp}\n\n"
            "Use it to download your file.\n"
            "Do NOT share this with anyone."
        )

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(SMTP_LOGIN, SMTP_PASSWORD)
            smtp.send_message(msg)

        return True

    except Exception as e:
        print("OTP Mail sending failed:", e)
        return False

# ---------- OTP SETTINGS ----------
generated_otp = None
otp_created_time = None
OTP_VALIDITY = 120
wrong_attempts = 0
MAX_ATTEMPTS = 3
otp_blocked = False
receiver_email = None
already_downloaded = False

# ---------- LOG ----------
def write_log(email, ip, status):
    with open("logs/download_log.txt", "a") as log:
        log.write(
            f"{datetime.now().strftime('%d-%m-%Y %I:%M %p')} | {email} | {ip} | {status}\n"
        )

# ---------- UPLOAD ----------
@app.route("/", methods=["GET", "POST"])
def upload_file():
    global generated_otp, otp_created_time, wrong_attempts, otp_blocked, receiver_email, already_downloaded

    if request.method == "POST":
        file = request.files["file"]
        receiver_email = request.form["email"]

        if file and file.filename:
            encrypted_data = cipher.encrypt(file.read())
            with open(f"encrypted_files/{file.filename}", "wb") as f:
                f.write(encrypted_data)

            generated_otp = random.randint(100000, 999999)
            otp_created_time = time.time()
            wrong_attempts = 0
            otp_blocked = False
            already_downloaded = False

            send_otp_email(receiver_email, generated_otp)

            flash("File uploaded & OTP sent!", "success")
            return redirect(url_for("verify_otp"))

    return render_template("upload.html")

# ---------- VERIFY OTP ----------
@app.route("/verify", methods=["GET", "POST"])
def verify_otp():
    global wrong_attempts, otp_blocked

    if request.method == "POST":
        user_otp = request.form["otp"]

        if otp_blocked:
            flash("OTP blocked", "danger")
            return redirect(url_for("upload_file"))

        if time.time() - otp_created_time > OTP_VALIDITY:
            otp_blocked = True
            flash("OTP expired", "danger")
            return redirect(url_for("upload_file"))

        if str(user_otp) == str(generated_otp):
            files = os.listdir("encrypted_files")
            fname = files[-1]
            fsize = round(os.path.getsize(f"encrypted_files/{fname}") / 1024, 2)

            write_log(receiver_email, request.remote_addr, "OTP VERIFIED")
            return render_template("download_ready.html", filename=fname, size=fsize)

        wrong_attempts += 1
        write_log(receiver_email, request.remote_addr, "WRONG OTP")

        if wrong_attempts >= MAX_ATTEMPTS:
            otp_blocked = True
            flash("OTP blocked", "danger")
        else:
            flash("Invalid OTP", "danger")

    return render_template("otp.html")

# ---------- DELETE ----------
def delayed_cleanup(paths):
    time.sleep(2)
    for p in paths:
        if os.path.exists(p):
            os.remove(p)

# ---------- DOWNLOAD ----------
@app.route("/download")
def download_file():
    global already_downloaded

    if already_downloaded:
        flash("Already downloaded", "danger")
        return redirect(url_for("upload_file"))

    files = os.listdir("encrypted_files")
    encrypted_file = files[-1]

    with open(f"encrypted_files/{encrypted_file}", "rb") as f:
        decrypted_data = cipher.decrypt(f.read())

    decrypted_path = f"encrypted_files/decrypted_{encrypted_file}"

    with open(decrypted_path, "wb") as f:
        f.write(decrypted_data)

    write_log(receiver_email, request.remote_addr, "SUCCESS")
    already_downloaded = True

    threading.Thread(
        target=delayed_cleanup,
        args=([f"encrypted_files/{encrypted_file}", decrypted_path],),
        daemon=True,
    ).start()

    return send_file(decrypted_path, as_attachment=True)

# ---------- RUN ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

