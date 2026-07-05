import smtplib

from email.mime.text import MIMEText
from app.constants import ENV, AnsiColor
from fastapi import Depends
from sqlalchemy.orm import Session
from app.core.database import SessionLocal, get_db

from services.configurations.configurations_services import ConfigurationsServices



class EmailManager:
    def __init__(self):
        self.email_address = ENV.EMAIL_ADDRESS
        self.email_password = ENV.EMAIL_PASSWORD
        self.smtp_server = ENV.SMTP_SERVER
        self.smtp_port = ENV.SMTP_PORT
        self.email_use_tls = ENV.EMAIL_USE_TLS
        self.email_use_ssl = ENV.EMAIL_USE_SSL

    def send_email(self, email_address: str, subject: str, body: str) -> bool:
        # Check if email sending is enabled in the configuration
        db: Session = Depends(get_db)
        configurationsServices = ConfigurationsServices(
            db=db,
            background_tasks=None,
            request=None,
            authorization=None
        )

        if not configurationsServices.get_email_settings()["enabled"]:
            print(f"{AnsiColor.RED}ERROR:{AnsiColor.RESET}    Email sending is disabled for {email_address}")
            return False
        
        
        msg = MIMEText(body, 'html')

        msg['Subject'] = subject
        msg['From'] = self.email_address
        msg['To'] = email_address

        try:
            smtp_class = smtplib.SMTP_SSL if self.email_use_ssl else smtplib.SMTP

            with smtp_class(self.smtp_server, self.smtp_port) as server:
                if self.email_use_tls and not self.email_use_ssl:
                    server.starttls()
                
                server.login(self.email_address, self.email_password)
                server.sendmail(self.email_address, email_address, msg.as_string())
            
            print(f"{AnsiColor.BLUE}INFO:{AnsiColor.RESET}     Email send on {email_address}")

            return True
        
        except Exception as e:
            print(f"{AnsiColor.RED}ERROR:{AnsiColor.RESET}    Failed to send email to {email_address}: {e}")
            return False

    def add_history(self, email_address: str, subject: str, body: str) -> None:
        # Implement logic to save email history to database or log
        pass





