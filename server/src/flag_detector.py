import json
import re
import time
import uuid
from logging import getLogger

from flask import g, request

logger = getLogger("app.flag_detector")

FLAG_REGEX = re.compile(
    r"FLAG\{[^}\r\n]{1,200}\}",
    re.IGNORECASE,
)

SUSPICIOUS_PATHS = {
    "/flag",
    "/flag.txt",
    "/get-flag",
}

# Normal watermark fields such as "key" are not suspicious alone.
SUSPICIOUS_PARAM_NAMES = {"flag"}

MAX_INSPECTION_CHARS = 2000


def contains_flag_field(value):
    """Check JSON field names without recording their values."""
    if isinstance(value, dict):
        return any(
            key.lower() in SUSPICIOUS_PARAM_NAMES
            or contains_flag_field(item)
            for key, item in value.items()
        )

    if isinstance(value, list):
        return any(contains_flag_field(item) for item in value)

    return False


def detect_flag_attempt():
    """Inspect incoming requests and log indicators without secret values."""
    g.request_start = time.time()
    g.request_id = str(uuid.uuid4())
    g.flag_attempt = False

    reasons = set()

    # Check known suspicious paths.
    normalized_path = request.path.rstrip("/").lower() or "/"

    if normalized_path in SUSPICIOUS_PATHS:
        reasons.add("suspicious_path")

    # Check all query values, including repeated parameters.
    for key, values in request.args.lists():
        if key.lower() in SUSPICIOUS_PARAM_NAMES:
            reasons.add("suspicious_query_parameter")

        if any(FLAG_REGEX.search(value) for value in values):
            reasons.add("flag_pattern_query")

    # Skip multipart bodies so uploaded files are not read by this hook.
    if request.mimetype != "multipart/form-data":
        if request.is_json:
            payload = request.get_json(silent=True)

            if contains_flag_field(payload):
                reasons.add("suspicious_json_field")

        # Cache the body so route handlers can still read it.
        body = request.get_data(cache=True, as_text=True)

        if FLAG_REGEX.search(body[:MAX_INSPECTION_CHARS]):
            reasons.add("flag_pattern_body")

    if reasons:
        event = {
            "event": "possible_flag_access_attempt",
            "timestamp": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(),
            ),
            "request_id": g.request_id,
            "client_ip": request.remote_addr,
            "method": request.method,
            # Log the route template instead of arbitrary URL path values.
            "route": (
                request.url_rule.rule
                if request.url_rule is not None
                else "<unmatched>"
            ),
            "details": {
                "where": sorted(reasons),
            },
        }

        logger.warning(json.dumps(event))

        g.flag_attempt = True
        g.flag_attempt_event = event

    # Returning None allows normal request handling to continue.
    return None