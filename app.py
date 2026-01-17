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

# -------- EMAIL SETTINGS --------
SENDER_EMAIL = os.environ.get("SENDER_EMAIL")
APP_PASSWORD = os.environ.get("APP_PASSWORD")

# -------- FOLDERS --------
if not os.path.exists("encrypted_files"):
    os.makedirs("encrypted_files")

if not os.path.exists("logs"):
    os.makedirs("logs")

# -------- ENCRYPTION --------
KEY_FILE = "secret.key"

if not os.path.exists(KEY_FILE):
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as kf:
        kf.write(key)
else:
    with open(KEY_FILE, "rb") as kf:
        key = kf.read()

cipher = Fernet(key)

# -------- SEND OTP MAIL --------
def send_otp_email(receiver, otp):
    try:
        msg = EmailMessage()
        msg["Subject"] = "Secure File Sharing - OTP"
        msg["From"] = SENDER_EMAIL
        msg["To"] = receiver

        msg.set_content(
            f"Your OTP is: {otp}\n\nUse it to download your file.\nDo NOT share this with anyone."
        )

        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as smtp:
            smtp.login(SENDER_EMAIL, APP_PASSWORD)
            smtp.send_message(msg)

        return True

    except Exception as e:
        print("❌ OTP Mail sending failed:", e)
        return False


# -------- GLOBAL OTP SETTINGS --------
generated_otp = None
otp_created_time = None
OTP_VALIDITY = 120
wrong_attempts = 0
MAX_ATTEMPTS = 3
otp_blocked = False
receiver_email = None
already_downloaded = False   # ⭐ download limit flag

# -------- LOG FUNCTION --------
def write_log(email, ip, status):
    with open("logs/download_log.txt", "a") as log:
        time_now = datetime.now().strftime("%d-%m-%Y %I:%M %p")
        log.write(f"{time_now} | {email} | {ip} | {status}\n")

# -------- UPLOAD + ENCRYPT --------
@app.route("/", methods=["GET", "POST"])
def upload_file():
    global generated_otp, otp_created_time, wrong_attempts, otp_blocked, receiver_email, already_downloaded

    if request.method == "POST":
        file = request.files["file"]
        receiver_email = request.form["email"]

        if file and file.filename != "":
            file_data = file.read()
            encrypted_data = cipher.encrypt(file_data)

            encrypted_path = os.path.join("encrypted_files", file.filename)
            with open(encrypted_path, "wb") as f:
                f.write(encrypted_data)

            generated_otp = random.randint(100000, 999999)
            otp_created_time = time.time()
            wrong_attempts = 0
            otp_blocked = False
            already_downloaded = False   # ⭐ reset on new upload

            send_otp_email(receiver_email, generated_otp)

            flash("File uploaded & encrypted. OTP sent to receiver email!", "success")
            return redirect(url_for("verify_otp"))

    return render_template("upload.html")

# -------- VERIFY OTP --------
@app.route("/verify", methods=["GET", "POST"])
def verify_otp():
    global wrong_attempts, otp_blocked

    if request.method == "POST":
        user_otp = request.form["otp"]

        # BLOCKED
        if otp_blocked:
            write_log(receiver_email, request.remote_addr, "BLOCKED")
            flash("OTP blocked — upload file again.", "danger")
            return redirect(url_for("upload_file"))

        # EXPIRED
        if time.time() - otp_created_time > OTP_VALIDITY:
            otp_blocked = True
            write_log(receiver_email, request.remote_addr, "OTP EXPIRED")
            flash("OTP expired — upload new file.", "danger")
            return redirect(url_for("upload_file"))

        # CORRECT OTP
        if str(user_otp) == str(generated_otp):

            # ---- SHOW FILE NAME + SIZE ----
            files = os.listdir("encrypted_files")
            file_name = files[-1]
            file_size = round(os.path.getsize(f"encrypted_files/{file_name}") / 1024, 2)

            write_log(receiver_email, request.remote_addr, "OTP VERIFIED")

            flash("OTP verified!", "success")

            return render_template(
                "download_ready.html",
                filename=file_name,
                size=file_size
            )

        # WRONG OTP
        else:
            wrong_attempts += 1
            write_log(receiver_email, request.remote_addr, "WRONG OTP")

            if wrong_attempts >= MAX_ATTEMPTS:
                otp_blocked = True
                write_log(receiver_email, request.remote_addr,
                          "TOO MANY ATTEMPTS — BLOCKED")
                flash("Too many wrong attempts — OTP blocked.", "danger")
            else:
                flash("Invalid OTP — try again.", "danger")

    return render_template("otp.html")

# -------- AUTO DELETE AFTER DOWNLOAD --------
def delayed_cleanup(paths):
    time.sleep(2)
    for p in paths:
        try:
            if os.path.exists(p):
                os.remove(p)
        except:
            pass

# -------- ADMIN LOG VIEW --------
@app.route("/admin/logs")
def view_logs():
    logs = []
    log_file_path = "logs/download_log.txt"

    if os.path.exists(log_file_path):
        with open(log_file_path, "r") as lf:
            for line in lf.readlines():
                parts = [p.strip() for p in line.split("|")]
                if len(parts) == 4:
                    logs.append({
                        "date": parts[0],
                        "email": parts[1],
                        "ip": parts[2],
                        "status": parts[3],
                    })

    return render_template("logs.html", logs=logs)

# -------- DOWNLOAD (ONE-TIME ONLY) --------
@app.route("/download")
def download_file():
    global already_downloaded

    # ⭐ block second time download
    if already_downloaded:
        flash("This file was already downloaded — access blocked.", "danger")
        write_log(receiver_email, request.remote_addr, "BLOCKED (SECOND DOWNLOAD)")
        return redirect(url_for("upload_file"))

    files = os.listdir("encrypted_files")
    if not files:
        flash("No file found!", "danger")
        return redirect(url_for("upload_file"))

    encrypted_filename = files[-1]
    encrypted_path = os.path.join("encrypted_files", encrypted_filename)

    with open(encrypted_path, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = cipher.decrypt(encrypted_data)

    decrypted_path = os.path.join("encrypted_files", "decrypted_" + encrypted_filename)

    with open(decrypted_path, "wb") as f:
        f.write(decrypted_data)

    write_log(receiver_email, request.remote_addr, "SUCCESS")
    already_downloaded = True   # ⭐ mark as used

    threading.Thread(
        target=delayed_cleanup,
        args=([encrypted_path, decrypted_path],),
        daemon=True,
    ).start()

    flash("File downloaded — it has been deleted from the server.", "info")
    return send_file(decrypted_path, as_attachment=True)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)




