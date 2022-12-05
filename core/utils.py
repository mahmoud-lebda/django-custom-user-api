from django.core.mail import EmailMessage
import smtplib
from email.mime.text import MIMEText
from django.conf import settings


class Util:
    """utility function"""

    @staticmethod
    def send_email(data):
        """
        sending email function
        if normal django send mail system not work
        comment EmailMessage function and use the commented function
        """

        email = EmailMessage(
            subject=data['email_subject'],
            body=data['email_body'],
            from_email='mahmoud.lebda@scopeims.com',
            to=[data['to_email']],
            headers={'Content-Type': 'text/plain'},
        )
        email.send()

        # sender = settings.EMAIL_HOST_USER
        # recipient = data['to_email']

        # # Create message
        # msg = MIMEText(data['email_body'])
        # msg['Subject'] = data['email_subject']
        # msg['From'] = sender
        # msg['To'] = recipient

        # # Create server object with SSL option
        # server = smtplib.SMTP_SSL(settings.EMAIL_HOST, settings.EMAIL_PORT)

        # # Perform operations via server
        # server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)
        # server.sendmail(sender, [recipient], msg.as_string())
        # server.quit()
