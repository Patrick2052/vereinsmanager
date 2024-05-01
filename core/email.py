import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from core.config import settings


def send_basic_email(receiver_email: str, subject: str, body: str):
    sender = "vereinsmanager-dev@patrick-huebler.de"

    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP(settings.smtp_server, settings.smtp_port)
    server.starttls()
    server.login(settings.email_address, settings.email_password)
    text = msg.as_string()
    server.sendmail(sender, receiver_email, text)
    server.quit()
