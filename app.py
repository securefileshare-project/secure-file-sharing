from flask import Flask, render_template, request, flash
import random
import smtplib
from email.message import EmailMessage
import os

app = Flask(__name__)
app.secret_key = "otp-test"

# ENV VARIABLES (Railway)
SMTP_SERVER = os.environ.get("SMTP_SERVER")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_LOGIN = os.environ.get("SMTP_LOGIN")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL")

generated_otp = None

def send_otp(receiver, otp):
    msg = EmailMessage()
    msg["Subject"] = "OTP Test"
    msg["From"] = SENDER_EMAIL
    msg["To"] = receiver
    msg.set_content(f"Your OTP is: {otp}")

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=20) as server:
        server.ehlo()
        server.starttls()
        server.login(SMTP_LOGIN, SMTP_PASSWORD)
        server.send_message(msg)

@app.route("/", methods=["GET", "POST"])
def index():
    global generated_otp

    if request.method == "POST":
        email = request.form.get("email")
        generated_otp = random.randint(100000, 999999)

        try:
            send_otp(email, generated_otp)
            flash("OTP sent successfully ✅", "success")
        except Exception as e:
            print("MAIL ERROR:", e)
            flash("OTP sending failed ❌", "danger")

    return """
    <h2>OTP Test</h2>
    <form method="post">
        <input name="email" placeholder="Enter email" required>
        <button type="submit">Send OTP</button>
    </form>
    """

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
