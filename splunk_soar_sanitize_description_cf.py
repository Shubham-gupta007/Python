r"""
Splunk SOAR Custom Function: sanitize_description
(Administration > Custom Functions > sanitize_description).

Builds the two BMC Remedy ITSM create-ticket values from a container:

  detailed_description  "Detailed analysis: - ...", "Recommendations: - ...",
                        "Description: - ..." and "Logs: - ..." sections from
                        the container's custom fields, joined by a line of
                        asterisks
  description           "CPX | ID: <CPX SOAR ID> | <use case>", the use case
                        being the second "|" part of the container name

Both come out JSON-escaped with no surrounding quotes, ready to sit inside
the quotes of the Format block that builds the Remedy fields JSON:

    "Description": "{0}",
    "Detailed_Decription": "{1}",

The custom fields hold JSON string literals ("...\"...\n..."). The previous
version flattened and escaped that text by hand, which broke on:

  * escaped line breaks inside log lines - F5 "HTTP/1.1\r\nHost:" stored as
    \\r\\n or \\\\r\\\\n. Replacing \n and \r one at a time left orphan
    backslashes ("\ \ ") and Remedy failed with "Invalid \escape"
  * other backslashes, e.g. TAX\nasser became "TAX\ asser"
  * pasted screenshots: ![](data:image/png;base64,...) - tens of KB of base64
  * emoji (flag icons), smart punctuation, invisible and control characters
  * a container that could not be loaded: description came out as "ul"

Now each field is decoded once into plain text, cleaned, and the result is
escaped exactly once with json.dumps. Text the previous version handled
correctly comes out unchanged: same labels, quotes, separators and line
breaks before IP addresses. Screenshots are dropped, flag emoji become their
country code (US, NL), escaped CRLFs inside logs become a space, and the
description is cut to Remedy's 100-character limit.

Editor setup (unchanged):
  Input   : container_id          | CEF Data Type = string
  Outputs : detailed_description  | CEF Data Type = string   (Item)
            description           | CEF Data Type = string   (Item)

Delete everything under the "Custom Code Goes Below This Line" marker and
paste exactly what

    python3 splunk_soar_sanitize_description_cf.py --body

prints. It is read from sanitize_description() below, so it cannot drift
from the tested code (test_splunk_soar_sanitize_description_cf.py).
"""

import inspect
import json
import sys
import types

try:
    import phantom.rules  # noqa: F401 - only exists inside SOAR
except ImportError:
    # Local runs and tests: a stand-in so the pasted block's `import phantom.rules` works.
    _rules = types.ModuleType("phantom.rules")
    _rules.debug = lambda *args, **kwargs: None
    _rules.get_container = lambda container_id: None
    sys.modules["phantom"] = types.ModuleType("phantom")
    sys.modules["phantom"].rules = _rules
    sys.modules["phantom.rules"] = _rules


def sanitize_description(container_id=None, **kwargs):
    """
    Sanititze the custom fields

    Args:
        container_id (CEF type: string)

    Returns a JSON-serializable object that implements the configured data paths:
        detailed_description (CEF type: string)
        description (CEF type: string)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import re
    import phantom.rules as phantom

    outputs = {"detailed_description": None, "description": None}

    separator = "\n" + "*" * 76 + " \n"
    description_limit = 100  # Remedy's short Description (Summary) field
    ip_pattern = re.compile(r"\b\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3}\b")

    def first_value(value):
        # SOAR datapaths can hand over a list (even a list of lists) instead of one value.
        if isinstance(value, (list, tuple)):
            return next((v for v in map(first_value, value) if v not in (None, "")), None)
        return value

    def to_text(value):
        if value is None:
            return ""
        if isinstance(value, (list, tuple)):
            parts = [part for part in (to_text(item) for item in value) if part.strip()]
            return "\n".join(dict.fromkeys(parts))
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value if isinstance(value, str) else str(value)

    def has_bare_quote(text):
        # A " that is not written as \" (no odd run of backslashes in front of it).
        return re.search(r'(?:^|[^\\])(?:\\\\)*"', text) is not None

    escapes = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}

    def unescape(text):
        # Undo one level of JSON escaping. Invalid escapes such as "\ " stay as literal
        # text instead of raising "Invalid \escape" the way json.loads does.
        return re.sub(
            r'\\(u[0-9a-fA-F]{4}|["\\/bfnrt])',
            lambda m: chr(int(m.group(1)[1:], 16)) if len(m.group(1)) == 5 else escapes[m.group(1)],
            text,
        )

    def decode(value):
        # Custom fields hold JSON string literals - "...\"...\n..." with the outer quotes.
        # Turn one back into plain text and remember the outer quotes, so the ticket
        # keeps showing   Label - "text"   as before.
        # Decode one layer only: the decoded text can itself contain \n or \t as data
        # (EXAMPLE\nasser, C:\temp).
        text = to_text(value).strip()
        if len(text) >= 2 and text[0] == text[-1] == '"' and not has_bare_quote(text[1:-1]):
            return unescape(text[1:-1]), True
        if not has_bare_quote(text) and ('"' in text or ("\\n" in text and "\n" not in text)):
            return unescape(text), False  # escaped, but without the outer quotes
        return text, False

    # Pasted screenshots: ![](data:image/...) - also with line breaks between ] and ( -
    # <img src="data:...">, bare data:...;base64,... blobs, and an empty ![]() left behind.
    data_uri = r"data:[\w.+-]+/[\w.+-]+(?:;[\w.+-]+=[\w.+-]+)*;base64,[A-Za-z0-9+/=%]*"
    embedded = re.compile(
        r"!\[[^\]\n]*\]\s*\(\s*<?" + data_uri + r">?\s*\)"
        r"|<img\b[^>]*?" + data_uri + r"[^>]*>"
        r"|" + data_uri +
        r"|!\[\](?:\s*\(\s*\))?",
        re.IGNORECASE,
    )

    def clean(text):
        text = embedded.sub(" ", text)
        # Escaped line breaks inside log lines, at any escaping depth (F5 "HTTP/1.1\r\nHost:").
        text = re.sub(r"\\+r\\+n", " ", text)
        # Escaped emoji leave UTF-16 surrogate halves: join the pairs, drop strays below.
        text = text.encode("utf-16", "surrogatepass").decode("utf-16", "replace")
        # Flag emoji are pairs of regional-indicator letters: keep them as the country code.
        text = re.sub("[\U0001F1E6-\U0001F1FF]", lambda m: chr(ord(m.group(0)) - 0x1F1E6 + ord("A")), text)
        text = text.translate({
            0x2010: "-", 0x2011: "-", 0x2012: "-", 0x2013: "-", 0x2014: "-", 0x2015: "-", 0x2212: "-",
            0x2018: "'", 0x2019: "'", 0x201A: "'", 0x201B: "'",
            0x201C: '"', 0x201D: '"', 0x201E: '"', 0x201F: '"',
            0x2022: "-", 0x2026: "...", 0x2260: "!=", 0x2264: "<=", 0x2265: ">=",
        })
        # Other emoji (outside the Basic Multilingual Plane), invisible and control characters.
        text = re.sub(
            r"[\U00010000-\U0010FFFF\U000000AD\U0000200B-\U0000200D\U00002060\U0000FE0E\U0000FE0F"
            r"\U0000FEFF\U0000FFFD\x00-\x08\x0e-\x1b\x7f-\x84\x86-\x9f]",
            "",
            text,
        )
        # One line per section, as before: line breaks become spaces and runs of
        # whitespace collapse to one space; tabs are kept.
        return re.sub(r"[^\S\t]+", " ", text)

    c_id = first_value(container_id)
    if isinstance(c_id, str) and c_id.strip().isdigit():
        c_id = int(c_id.strip())
    phantom.debug(f"c_id found: {c_id}")

    container_object = phantom.get_container(c_id) if c_id not in (None, "") else None
    if not container_object:
        phantom.debug(f"sanitize_description: no container found for container_id={container_id!r}")
    else:
        # Field names match whatever their case and spaces/underscores ("CPX SOAR ID", "cpx_soar_id").
        custom_fields = {
            re.sub(r"[\s_]+", " ", str(key)).strip().lower(): value
            for key, value in (container_object.get("custom_fields") or {}).items()
        }
        sections = [
            ("Detailed analysis:", custom_fields.get("detailed analysis")),
            ("Recommendations:", custom_fields.get("recommendations")),
            ("Description:", custom_fields.get("description")),
            ("Logs:", custom_fields.get("logs")),
            # ("MITRE Technique:", custom_fields.get("mitre technique")),
            # ("MITRE Tactic:", custom_fields.get("mitre tactic")),
            # ("Occurred Date:", custom_fields.get("occurred date")),
            # ("Container Description:", container_object.get("description")),
        ]
        lines = []
        for label, value in sections:
            text, quoted = decode(value)
            text = clean(text)
            if label == "Detailed analysis:":
                # Every IP address starts a new line in the ticket.
                text = ip_pattern.sub(lambda m: "\n" + m.group(0), text).replace("[.]", ".")
            lines.append(f'{label} - "{text}"' if quoted else f"{label} - {text.strip()}")
        detailed_description = separator.join(lines)

        name = clean(decode(container_object.get("name"))[0]).strip()
        parts = [part.strip() for part in name.split("|")]
        cpx_soar_id = clean(decode(custom_fields.get("cpx soar id"))[0]).strip() or "None"
        description = f"CPX | ID: {cpx_soar_id} | " + (parts[1] if len(parts) > 1 else name)
        if len(description) > description_limit:
            description = description[: description_limit - 3].rstrip() + "..."

        outputs["detailed_description"] = json.dumps(detailed_description)[1:-1]  # escaped once, no outer quotes
        outputs["description"] = json.dumps(description)[1:-1]
        phantom.debug(f"description found: {outputs['description']}")
        phantom.debug(f"detailed_description found: {outputs['detailed_description']}")

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs


def custom_function_body():
    """The block to paste under SOAR's "Custom Code Goes Below This Line" marker, read from the function above."""
    lines = inspect.getsource(sanitize_description).splitlines()
    start = next(i for i, line in enumerate(lines) if "Custom Code Goes Below This Line" in line) + 1
    return "\n".join(lines[start:]).strip("\n") + "\n"


CUSTOM_FUNCTION_BODY = custom_function_body()


if __name__ == "__main__":
    if "--body" in sys.argv[1:]:
        print(CUSTOM_FUNCTION_BODY, end="")
        sys.exit(0)

    # A container shaped like the ones that broke ticket creation (made-up data).
    flag = "\N{REGIONAL INDICATOR SYMBOL LETTER N}\N{REGIONAL INDICATOR SYMBOL LETTER L}"
    sample = {
        "id": 101,
        "name": "SOC Alert | 8012_CVE-2026-6303 -wp2shell - Pre-Authentication RCE | high",
        "custom_fields": {
            "CPX SOAR ID": "3566875",
            "Detailed Analysis": json.dumps(
                f"Dear Team,\nSource IP: 203.0.113.40\nCountry {flag} Netherlands\n"
                "Screenshot: ![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==)"
            ),
            "Recommendations": json.dumps("Block 203[.]0[.]113[.]40 at the WAF. "),
            "Description": json.dumps('search_name="Threat - 8012 - Rule", src="203[.]0[.]113[.]40"'),
            "Logs": json.dumps('request="GET / HTTP/1.1\\r\\nHost: www[.]example[.]com" user=EXAMPLE\\nasser'),
        },
    }
    sys.modules["phantom.rules"].get_container = lambda container_id: sample

    result = sanitize_description(container_id=[101])
    payload = json.loads(
        '{"Description": "%s", "Detailed_Decription": "%s"}' % (result["description"], result["detailed_description"])
    )
    print("description          :", result["description"])
    print("detailed_description :", result["detailed_description"], "\n")
    print("Remedy receives (the JSON parses):")
    print(payload["Description"])
    print(payload["Detailed_Decription"])
