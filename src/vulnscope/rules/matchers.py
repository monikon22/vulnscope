"""Rule matcher implementations."""

from __future__ import annotations

import html
import re

from vulnscope.rules.schema import Rule
from vulnscope.scanner.http_client import HttpObservation


def _body(observation: HttpObservation) -> str:
    return observation.response_text or ""


def match_rule(rule: Rule, observation: HttpObservation, payload: str | None = None) -> str | None:
    """Return evidence when a rule matches the observation."""

    match = rule.match
    body = _body(observation)
    lower_headers = {key.lower(): value for key, value in observation.response_headers.items()}

    if match.type == "contains_any":
        values = match.values or rule.payloads
        for value in values:
            if value and value.lower() in body.lower():
                return f"Response contains marker: {value}"
        return None

    if match.type == "contains_all":
        values = match.values or rule.payloads
        if values and all(value.lower() in body.lower() for value in values):
            return f"Response contains all markers: {', '.join(values)}"
        return None

    if match.type == "regex":
        patterns = [match.pattern] if match.pattern else match.values
        for pattern in patterns:
            if pattern and re.search(pattern, body, re.IGNORECASE | re.MULTILINE):
                return f"Response matched regex: {pattern}"
        return None

    if match.type == "reflected_without_encoding":
        candidate = payload or (rule.payloads[0] if rule.payloads else "")
        if candidate and candidate in body and html.escape(candidate) not in body:
            return f"Payload reflected without HTML encoding: {candidate}"
        return None

    if match.type == "missing_header":
        header = (match.header or "").lower()
        if header and header not in lower_headers:
            return f"Missing security header: {match.header}"
        return None

    if match.type == "insecure_cookie":
        cookies = [
            value
            for key, value in observation.response_headers.items()
            if key.lower() == "set-cookie"
        ]
        for cookie in cookies:
            lowered = cookie.lower()
            if "secure" not in lowered or "httponly" not in lowered or "samesite" not in lowered:
                return f"Cookie missing security attributes: {cookie[:120]}"
        return None

    if match.type == "server_error":
        if observation.status_code >= 500:
            return f"Server returned HTTP {observation.status_code}"
        return None

    if match.type == "technology_detected":
        values = match.values
        headers_blob = " ".join(f"{k}: {v}" for k, v in observation.response_headers.items())
        combined = f"{headers_blob}\n{body}"
        for value in values:
            if value.lower() in combined.lower():
                return f"Detected technology marker: {value}"
        return None

    if match.type == "status_code_changed":
        if (
            observation.baseline_status_code is not None
            and observation.status_code != observation.baseline_status_code
        ):
            return (
                f"Status changed from {observation.baseline_status_code} "
                f"to {observation.status_code}"
            )
        return None

    if match.type == "response_length_delta":
        threshold = match.threshold or 500
        if (
            observation.baseline_size is not None
            and abs(observation.size_bytes - observation.baseline_size) >= threshold
        ):
            return f"Response length delta exceeded {threshold} bytes"
        return None

    return None
