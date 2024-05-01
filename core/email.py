import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from core.config import settings
from typing import Literal


def send_basic_email(receiver_email: str,
                     subject: str,
                     body: str,
                     msg_type: Literal["html", "plain"] = "plain"):
    sender = "vereinsmanager-dev@patrick-huebler.de"

    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, msg_type))

    server = smtplib.SMTP(settings.smtp_server, settings.smtp_port)
    server.starttls()
    server.login(settings.email_address, settings.email_password)
    text = msg.as_string()
    server.sendmail(sender, receiver_email, text)
    server.quit()


# def send_email_confirmation(user_id)

def send_email_confirmation(receiver_email: str, confirmation_token: str):
    subject = "Vereinsmanager Email Confirmation"
    confirmation_link = f"http://localhost:8000/auth/confirm-email?token={confirmation_token}"
    body = f"""\
    <html>
      <body>
        <p>Thank you for registering. Please click on the following link to confirm your email:<br>
           <a href="{confirmation_link}">Confirm Email</a> <br>
           this link is valid for 24 hours
        </p>
      </body>
    </html>
    """
    send_basic_email(receiver_email, subject, body, "html")


def send_password_recovery(receiver_email: str, pw_token: str):
    subject = "Vereinsmanager Password Reset"
    confirmation_link = f"{settings.password_recovery_redirect_url}?token={pw_token}"
    body = f"""\
    <html>
      <body>
        <p>Click on link to reset password<br>
           <a href="{confirmation_link}">Reset Password</a> 
        </p>
      </body>
    </html>
    """
    send_basic_email(receiver_email, subject, body, "html")