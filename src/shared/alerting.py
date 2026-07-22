"""Send a plain-text email alert via the host's ``mailx``.

Tool-agnostic: any script can build an :class:`EmailAlerter` and call
:meth:`~EmailAlerter.send`. Delivery relies on the host's existing ``mailx`` and
mail setup (local MTA / relay) — there are no SMTP knobs here. A delivery failure
raises :class:`AlertError`; callers typically log it rather than let it mask the
condition that triggered the alert.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass

logger = logging.getLogger("shared.alerting")

DEFAULT_SUBJECT = "Automated alert"


class AlertError(RuntimeError):
    """Raised when the alert email could not be sent."""


@dataclass(frozen=True)
class EmailAlerter:
    """Sends a plain-text alert email by shelling out to ``mailx``.

    ``recipients`` are passed as positional ``mailx`` arguments; ``sender`` (if
    set) becomes ``-r <sender>``. The body is fed on stdin, and the command is
    run without a shell (list-form argv), so there is no injection surface.
    """

    recipients: list[str]
    sender: str | None = None
    subject: str = DEFAULT_SUBJECT
    mailx_path: str = "mailx"

    def send(self, body: str) -> None:
        """Send ``body`` as the email content; raise :class:`AlertError` on failure."""
        cmd = [self.mailx_path, "-s", self.subject]
        if self.sender:
            cmd += ["-r", self.sender]
        cmd += self.recipients

        try:
            subprocess.run(cmd, input=body, text=True, capture_output=True, check=True)
        except FileNotFoundError as exc:
            raise AlertError(
                f"{self.mailx_path!r} not found on PATH; install it or disable "
                "email alerts"
            ) from exc
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip()
            raise AlertError(f"mailx exited {exc.returncode}: {stderr}") from exc

        logger.info("Sent alert email to %s", ", ".join(self.recipients))
