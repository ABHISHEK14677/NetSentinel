"""
email_notifier.py
=================
Email alert delivery system for NetSentinel using Python smtplib.

Reads configuration from environment variables and delivers security alerts
asynchronously via a background sender thread.  All failures are logged at
ERROR level; no exceptions propagate to the caller.
"""

from __future__ import annotations

import email.encoders
import email.mime.base
import email.mime.multipart
import email.mime.text
import logging
import os
import queue
import smtplib
import threading
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity ordering used for "minimum severity" gate
# ---------------------------------------------------------------------------
_SEVERITY_ORDER: Dict[str, int] = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class EmailNotifier:
    """
    Asynchronous email alert notifier for NetSentinel.

    Configuration is loaded entirely from environment variables so that no
    secrets need to be hard-coded.  When SMTP is not enabled (or not
    configured), every public method becomes a no-op logged at DEBUG level.

    Attributes
    ----------
    SMTP_HOST : str
        Outgoing SMTP server hostname.
    SMTP_PORT : int
        SMTP server port (default 587 for STARTTLS).
    SMTP_USER : str
        SMTP authentication username / login address.
    SMTP_PASSWORD : str
        SMTP authentication password.
    SMTP_FROM : str
        Envelope-from address shown in the *From* header.
    SMTP_TO : List[str]
        Comma-separated list of recipient addresses parsed into a list.
    SMTP_ENABLED : bool
        Master switch; emails are sent only when ``True``.
    MIN_SEVERITY_TO_EMAIL : str
        Minimum alert severity that triggers an email.
    email_queue : queue.Queue
        Unbounded FIFO queue consumed by the background sender thread.
    """

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(self) -> None:
        """Load configuration from environment variables and start the background sender thread."""
        self.SMTP_HOST: str = os.getenv("NETSENTINEL_SMTP_HOST", "smtp.gmail.com")
        self.SMTP_PORT: int = int(os.getenv("NETSENTINEL_SMTP_PORT", "587"))
        self.SMTP_USER: str = os.getenv("NETSENTINEL_SMTP_USER", "")
        self.SMTP_PASSWORD: str = os.getenv("NETSENTINEL_SMTP_PASS", "")
        self.SMTP_FROM: str = os.getenv("NETSENTINEL_SMTP_FROM", "netsentinel@localhost")
        self.SMTP_TO: List[str] = [
            addr.strip()
            for addr in os.getenv("NETSENTINEL_SMTP_TO", "").split(",")
            if addr.strip()
        ]
        self.SMTP_ENABLED: bool = (
            os.getenv("NETSENTINEL_SMTP_ENABLED", "false").lower() == "true"
        )
        self.MIN_SEVERITY_TO_EMAIL: str = os.getenv(
            "NETSENTINEL_EMAIL_MIN_SEVERITY", "HIGH"
        ).upper()

        self.email_queue: queue.Queue = queue.Queue()

        # Start the background sender daemon thread
        self._thread = threading.Thread(
            target=self._sender_thread,
            name="EmailNotifier-Sender",
            daemon=True,
        )
        self._thread.start()
        logger.debug(
            "EmailNotifier initialised (enabled=%s, min_severity=%s, host=%s:%d)",
            self.SMTP_ENABLED,
            self.MIN_SEVERITY_TO_EMAIL,
            self.SMTP_HOST,
            self.SMTP_PORT,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_alert(
        self,
        subject: str,
        body: str,
        severity: str,
        attachments: Optional[List[str]] = None,
    ) -> None:
        """
        Enqueue an email alert if SMTP is enabled and severity meets the threshold.

        Parameters
        ----------
        subject : str
            Email subject line.
        body : str
            Plain-text email body.
        severity : str
            One of INFO / LOW / MEDIUM / HIGH / CRITICAL.
        attachments : list of str, optional
            File-system paths to files that should be attached (e.g. .pcap).
        """
        if not self.SMTP_ENABLED or not self.SMTP_USER:
            logger.debug("Email not configured, skipping")
            return

        sev_upper = severity.upper()
        if _SEVERITY_ORDER.get(sev_upper, -1) < _SEVERITY_ORDER.get(
            self.MIN_SEVERITY_TO_EMAIL, 3
        ):
            logger.debug(
                "Alert severity %s below threshold %s, skipping email",
                sev_upper,
                self.MIN_SEVERITY_TO_EMAIL,
            )
            return

        self.email_queue.put(
            {
                "subject": subject,
                "body": body,
                "attachments": attachments or [],
            }
        )
        logger.info("Email alert enqueued: %s", subject)

    def send_anomaly_alert(
        self,
        mac: str,
        anomaly_score: float,
        feature_vector: Dict[str, float],
        pcap_path: Optional[str] = None,
    ) -> None:
        """
        Convenience method to send a formatted ML anomaly alert email.

        Parameters
        ----------
        mac : str
            MAC address of the suspicious device.
        anomaly_score : float
            Numeric anomaly / outlier score from the ML engine.
        feature_vector : dict
            Mapping of feature name → value used for the anomaly decision.
        pcap_path : str, optional
            Path to a .pcap capture file to attach as evidence.
        """
        subject = (
            f"[NetSentinel ALERT] Anomaly detected: MAC {mac} score {anomaly_score:.1f}"
        )

        # Build a plain-text feature breakdown table
        rows = "\n".join(
            f"  {name:<35} {value}" for name, value in sorted(feature_vector.items())
        )
        body = (
            f"NetSentinel has detected anomalous network behaviour.\n\n"
            f"Device MAC  : {mac}\n"
            f"Anomaly Score: {anomaly_score:.4f}\n\n"
            f"Feature Breakdown:\n"
            f"{'  Feature':<37} Value\n"
            f"  {'-' * 50}\n"
            f"{rows}\n\n"
            f"Please investigate this device immediately.\n"
        )

        attachments: List[str] = []
        if pcap_path:
            attachments.append(pcap_path)

        self.send_alert(subject, body, severity="HIGH", attachments=attachments)

    def send_spoofing_alert(self, spoof_info: Dict) -> None:
        """
        Convenience method to send a MAC/IP spoofing alert email.

        Parameters
        ----------
        spoof_info : dict
            Dictionary containing spoofing details.  Recognised keys include:
            ``mac``, ``ip``, ``original_mac``, ``original_ip``, ``confidence``,
            ``timestamp``, and any extra context fields.
        """
        mac = spoof_info.get("mac", "unknown")
        ip = spoof_info.get("ip", "unknown")
        original_mac = spoof_info.get("original_mac", "N/A")
        original_ip = spoof_info.get("original_ip", "N/A")
        confidence = spoof_info.get("confidence", "N/A")
        timestamp = spoof_info.get("timestamp", "N/A")

        subject = f"[NetSentinel ALERT] MAC/IP Spoofing Detected: {mac} / {ip}"
        body = (
            f"NetSentinel has detected a possible MAC/IP spoofing attack.\n\n"
            f"Suspicious MAC  : {mac}\n"
            f"Suspicious IP   : {ip}\n"
            f"Original MAC    : {original_mac}\n"
            f"Original IP     : {original_ip}\n"
            f"Confidence      : {confidence}\n"
            f"Detected at     : {timestamp}\n\n"
            f"Additional context:\n"
        )
        for key, value in spoof_info.items():
            if key not in {
                "mac", "ip", "original_mac", "original_ip", "confidence", "timestamp"
            }:
                body += f"  {key}: {value}\n"

        body += "\nPlease investigate this event immediately.\n"
        self.send_alert(subject, body, severity="CRITICAL")

    def get_status(self) -> Dict:
        """
        Return a summary of the current email notifier configuration.

        Returns
        -------
        dict
            Keys: enabled, smtp_host, smtp_port, smtp_from,
                  recipients_count, min_severity, queue_size.
        """
        return {
            "enabled": self.SMTP_ENABLED,
            "smtp_host": self.SMTP_HOST,
            "smtp_port": self.SMTP_PORT,
            "smtp_from": self.SMTP_FROM,
            "recipients_count": len(self.SMTP_TO),
            "min_severity": self.MIN_SEVERITY_TO_EMAIL,
            "queue_size": self.email_queue.qsize(),
        }

    def test_connection(self) -> Dict:
        """
        Attempt an SMTP connection without sending any mail.

        Returns
        -------
        dict
            ``{"success": bool, "message": str}``
        """
        if not self.SMTP_ENABLED or not self.SMTP_USER:
            return {"success": False, "message": "Email not configured (disabled or no SMTP user)"}

        try:
            with smtplib.SMTP(self.SMTP_HOST, self.SMTP_PORT, timeout=10) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(self.SMTP_USER, self.SMTP_PASSWORD)
            return {"success": True, "message": f"Connected to {self.SMTP_HOST}:{self.SMTP_PORT} successfully"}
        except Exception as exc:  # noqa: BLE001
            logger.error("SMTP test connection failed: %s", exc)
            return {"success": False, "message": str(exc)}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _send_email(
        self,
        subject: str,
        body: str,
        attachments: List[str],
    ) -> None:
        """
        Construct and deliver an email via SMTP with STARTTLS.

        Parameters
        ----------
        subject : str
            Email subject line.
        body : str
            Plain-text email body.
        attachments : list of str
            Paths to files to attach.  Non-existent paths are skipped with a
            warning rather than raising an exception.
        """
        if not self.SMTP_TO:
            logger.warning("No recipient addresses configured, discarding email: %s", subject)
            return

        try:
            msg = email.mime.multipart.MIMEMultipart()
            msg["From"] = self.SMTP_FROM
            msg["To"] = ", ".join(self.SMTP_TO)
            msg["Subject"] = subject

            msg.attach(email.mime.text.MIMEText(body, "plain", "utf-8"))

            for path in attachments:
                if not os.path.isfile(path):
                    logger.warning("Attachment not found, skipping: %s", path)
                    continue
                try:
                    with open(path, "rb") as fh:
                        data = fh.read()
                    part = email.mime.base.MIMEBase("application", "octet-stream")
                    part.set_payload(data)
                    email.encoders.encode_base64(part)
                    part.add_header(
                        "Content-Disposition",
                        "attachment",
                        filename=os.path.basename(path),
                    )
                    msg.attach(part)
                except OSError as exc:
                    logger.warning("Could not read attachment %s: %s", path, exc)

            with smtplib.SMTP(self.SMTP_HOST, self.SMTP_PORT, timeout=30) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                smtp.login(self.SMTP_USER, self.SMTP_PASSWORD)
                smtp.sendmail(self.SMTP_FROM, self.SMTP_TO, msg.as_bytes())

            logger.info(
                "Email sent successfully to %d recipient(s): %s",
                len(self.SMTP_TO),
                subject,
            )

        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to send email '%s': %s", subject, exc)

    def _sender_thread(self) -> None:
        """
        Background daemon thread that consumes :attr:`email_queue` and calls
        :meth:`_send_email` for each item.

        The thread runs indefinitely and handles all exceptions internally so
        that a transient SMTP failure never crashes the background worker.
        """
        logger.debug("EmailNotifier sender thread started")
        while True:
            try:
                item = self.email_queue.get(block=True, timeout=1)
                self._send_email(
                    subject=item["subject"],
                    body=item["body"],
                    attachments=item.get("attachments", []),
                )
                self.email_queue.task_done()
            except queue.Empty:
                continue
            except Exception as exc:  # noqa: BLE001
                logger.error("Unexpected error in EmailNotifier sender thread: %s", exc)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

email_notifier = EmailNotifier()
