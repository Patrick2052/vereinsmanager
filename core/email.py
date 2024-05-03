import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from core.config import settings
from typing import Literal
from datetime import datetime
from core.logger import main_logger
import requests
from core.external import get_ip_location


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


def send_new_login_notification(receiver_email: str,
                                client_ip: str,
                                user_agent: str):
    # send warning email to user

    # figure out location
    location = get_ip_location(client_ip)

    text = f"""
    <h2>Vereinsmanager - new login to your account</h2>
    <br/>
    <ul>
    <li>
      <strong>
        ip: {client_ip} - {location}
      </strong>
    </li>
    <li>
    <strong>
      user-agent: {user_agent}
    </strong>
    </li>
    <li>
    <strong>
      at {str(datetime.now())}
    </strong>
    </li>
    </ul>

    <p>If it was you who logged in you can ignore this email </p>
    """
    try:
        send_basic_email(body=text, receiver_email=receiver_email, subject="vereinsmanager - new login", msg_type="html")
    except Exception as e:
        main_logger.exception(f"Sending New Login Warning Email to {receiver_email} failed",
                              exc_info=e)