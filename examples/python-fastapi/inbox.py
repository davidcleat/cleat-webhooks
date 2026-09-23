"""What this example does with a verified message.

Replace this with your own work: look the code up against the signup you
started, forward it, unblock a waiting job. Keep it fast (see the note in
main.py about the 10 second budget) and do the slow parts on a queue.
"""

from __future__ import annotations

from typing import Any

# Everything this process has handled, oldest first. In-memory, per-process.
handled: list[dict[str, Any]] = []


def handle_message(message: dict[str, Any], *, event_type: str) -> None:
    # `code` is Cleat's extraction of the code, for display, and it is best
    # effort: it can be None even when the text clearly contains something. Read
    # `body` whenever it matters. `body` is the full text, and for a code read
    # out over an automated call it is the transcript of that call. Nothing in
    # the payload marks a message as having come from a call.
    code = message.get("code")
    if not isinstance(code, str):
        code = None

    handled.append(
        {"id": message["id"], "type": event_type, "code": code, "body": message.get("body")}
    )

    line = message.get("line") or {}
    print(
        f"[cleat] {event_type} {message['id']} from {message.get('from')} on {line.get('phone')}"
        + (f" code={code}" if code else " (no code extracted, read data.body)")
    )


def reset() -> None:
    handled.clear()
