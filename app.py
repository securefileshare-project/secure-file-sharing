from flask import Flask, render_template, request, send_file, flash, redirect, url_for
import os, random, time, threading
from cryptography.fernet import Fernet
from email.message import EmailMessage
import smtplib
from datetime import datetime

app = Flask(__name__)
app.secret_key = "securefilesharingproject"

# ================= SMTP (BREVO) =================
SMTP_SERVER = os.environ.get("SMTP_SERVER")        # smtp-relay.brevo.com
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_LOGIN = os.environ.get("SMTP_LOGIN")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL")

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

# ================= OTP SETTINGS =================
generated_otp = None
otp_created_time = None
OTP_VALIDITY = 180  # seconds
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

# ================= SEND OTP =================
def send_otp_email(receiver, otp):
    try:
        msg = EmailMessage()
        msg["Subject"] = "Secure File Sharing - OTP"
        msg["From"] = SENDER_EMAIL
        msg["To"] = receiver
        msg.set_content(f"Your OTP is: {otp}\n\nDo not share this OTP.")

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_LOGIN, SMTP_PASSWORD)
            server.send_message(msg)

        return True
    except Exception as e:
        print("MAIL ERROR:", e)
        return False

# ================= UPLOAD =================
@app.route("/", methods=["GET", "POST"])
def upload_file():
    global generated_otp, otp_created_time, wrong_attempts
    global otp_blocked, receiver_email, already_downloaded

    if request.method == "POST":
        file = request.files.get("file")
        receiver_email = request.form.get("email")

        if not file or file.filename == "":
            flash("Please select a file", "danger")
            return redirect(url_for("upload_file"))

        encrypted = cipher.encrypt(file.read())
        path = os.path.join("encrypted_files", file.filename)

        with open(path, "wb") as f:
            f.write(encrypted)

        generated_otp = random.randint(100000, 999999)
        otp_created_time = time.time()
        wrong_attempts = 0
        otp_blocked = False
        already_downloaded = False

        if not send_otp_email(receiver_email, generated_otp):
            flash("OTP email failed", "danger")
            return redirect(url_for("upload_file"))

        flash("File uploaded. OTP sent to receiver email.", "success")
        return redirect(url_for("verify_otp"))

    return render_template("upload.html")

# ================= VERIFY OTP =================
@app.route("/verify", methods=["GET", "POST"])
def verify_otp():
    global wrong_attempts, otp_blocked

    if request.method == "POST":
        user_otp = request.form.get("otp")

        if otp_blocked:
            flash("OTP blocked. Upload again.", "danger")
            return redirect(url_for("upload_file"))

        if time.time() - otp_created_time > OTP_VALIDITY:
            otp_blocked = True
            flash("OTP expired.", "danger")
            return redirect(url_for("upload_file"))

        if str(user_otp) == str(generated_otp):
            files = os.listdir("encrypted_files")
            fname = files[-1]
            size = round(os.path.getsize("encrypted_files/" + fname) / 1024, 2)
            write_log(receiver_email, request.remote_addr, "OTP VERIFIED")
            return render_template("download_ready.html", filename=fname, size=size)

        wrong_attempts += 1
        if wrong_attempts >= MAX_ATTEMPTS:
            otp_blocked = True
            flash("Too many wrong attempts.", "danger")
        else:
            flash("Invalid OTP.", "danger")

    return render_template("otp.html")

# ================= DOWNLOAD =================
@app.route("/download")
def download():
    global already_downloaded

    if already_downloaded:
        flash("File already downloaded.", "danger")
        return redirect(url_for("upload_file"))

    files = os.listdir("encrypted_files")
    fname = files[-1]
    enc_path = "encrypted_files/" + fname

    with open(enc_path, "rb") as f:
        decrypted = cipher.decrypt(f.read())

    dec_path = "encrypted_files/decrypted_" + fname
    with open(dec_path, "wb") as f:
        f.write(decrypted)

    already_downloaded = True
    write_log(receiver_email, request.remote_addr, "SUCCESS")

    threading.Thread(
        target=lambda: time.sleep(3) or os.remove(enc_path) or os.remove(dec_path),
        daemon=True
    ).start()

    return send_file(dec_path, as_attachment=True)

# ================= RUN =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

