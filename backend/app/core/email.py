"""Outbound email over SMTP."""

import smtplib
from email.message import EmailMessage

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)


class EmailNotConfigured(RuntimeError):
    pass


def send_email(to: str, subject: str, body: str) -> None:
    s = get_settings()
    if not s.smtp_host:
        raise EmailNotConfigured("SMTP is not configured (CTEM_SMTP_HOST)")
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = s.smtp_from, to, subject.replace("\n", " ").replace("\r", " ")
    msg.set_content(body)
    with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=15) as smtp:
        if s.smtp_starttls:
            smtp.starttls()
        if s.smtp_username:
            smtp.login(s.smtp_username, s.smtp_password)
        smtp.send_message(msg)


def send_account_email(to: str, subject: str, body: str, *, dev_link: str | None = None) -> bool:
    """Send an account email. Without SMTP the message is not delivered; in development the
    action link is written to the log so the flow can still be exercised locally."""
    try:
        send_email(to, subject, body)
        return True
    except EmailNotConfigured:
        s = get_settings()
        if s.env == "development" and dev_link:
            log.warning("email_not_sent_smtp_unconfigured", subject=subject, dev_action_link=dev_link)
        else:
            log.warning("email_not_sent_smtp_unconfigured", subject=subject)
        return False
    except (smtplib.SMTPException, OSError) as exc:
        log.error("email_send_failed", subject=subject, error=str(exc))
        return False
