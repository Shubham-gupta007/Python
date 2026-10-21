r"""
Splunk SOAR "Custom Functions" library entry (Administration > Custom
Functions > New Custom Function - the /custom_function/ editor, Python 3.13
stub with a bare **kwargs signature and a plain `return outputs` dict).

Makes any Description / Detailed_Decription text safe to drop into the BMC
Remedy ITSM create-ticket JSON, whatever shape it arrives in. Each of these
broke ticket creation before:

  * raw text with real newlines or bare " quotes
      -> "Invalid control character" / "Expecting ',' delimiter"
  * text that is ALREADY JSON-escaped (\" and \n written as two characters)
    but also carries invalid escapes such as "\ " (backslash + space)
      -> "Invalid \escape"
  * already-escaped text with real line breaks mixed in, e.g. around a
    pasted screenshot
      -> "Invalid control character"
  * pasted screenshots: ![](data:image/png;base64,...) blobs - tens of KB
    of base64 that must never reach the ticket
  * emoji (flag icons such as \ud83c\uddfa\ud83c\uddf8), smart punctuation,
    zero-width and control characters

What it does, in order:
  1. Accepts a string, a list (SOAR datapaths often return lists, even
     lists of lists), bytes, a number, or None.
  2. Detects text that is already JSON-escaped and decodes it, keeping
     invalid escapes like "\ " as literal text instead of failing. Escaping
     it again without this would show \" and \n literally in the ticket.
  3. Removes embedded data: URIs - markdown ![](data:...) images (also with
     line breaks between ] and (), <img src="data:..."> tags and bare
     data:...;base64,... blobs.
  4. Turns flag emoji into their country code (US, NL), maps smart quotes,
     dashes, <=, >= and similar to ASCII, and drops other emoji plus
     invisible and control characters. Letters of other scripts (e.g.
     Arabic) are kept.
  5. Optionally truncates to max_length characters.
  6. Escapes the result exactly once.

Editor setup (left panel):
  Name              : sanitize_description (or any name you like)
  Add Input         : Name = description        | Data Type = string
  Add Input         : Name = max_length         | Data Type = string
                       (optional - leave it unwired for no limit, or e.g.
                       100 when feeding Remedy's short Description field)
  Add Output (Item) : Name = description        | Data Type = string
  Add Output (Item) : Name = description_plain  | Data Type = string
                       (output Names must match the keys set on `outputs`)

Which output goes where:
  description        escaped, no surrounding quotes - put it INSIDE the
                     quotes of a JSON template you build in a Format block:
                         "Detailed_Decription": "{0}"
  description_plain  clean, unescaped text - for blocks that escape on
                     their own (splunk_soar_build_remedy_fields_json.py, or
                     a JSON-typed action parameter). Never put this one
                     inside a hand-built JSON template.

Only the code between the "Custom Code Goes Below This Line" markers is
editable in SOAR's editor. Paste exactly what

    python3 splunk_soar_sanitize_description_cf.py --body

prints there. It is read straight from sanitize_description() below, so it
cannot drift from the tested code (test_splunk_soar_sanitize_description_cf.py).
"""

import inspect
import json
import sys


def sanitize_description(**kwargs):
    """
    Returns a JSON-serializable object that implements the configured data paths:
        description, description_plain
    """

    ################################################################################
    ## Custom Code Goes Below This Line
    ################################################################################

    import json
    import re

    outputs = {}

    def to_text(value):
        # SOAR datapaths can hand over a list (even a list of lists) instead of a string.
        if value is None:
            return ""
        if isinstance(value, (list, tuple)):
            parts = [part for part in (to_text(item) for item in value) if part.strip()]
            return "\n".join(dict.fromkeys(parts))  # same text from several artifacts only once
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value if isinstance(value, str) else str(value)

    def looks_escaped(text):
        # Already-escaped text writes every " as \" (an odd run of backslashes before it).
        if re.search(r'(?:^|[^\\])(?:\\\\)*"', text):
            return False  # a bare " means plain text
        if '"' in text:
            return True
        # No quotes at all: escaped text is one physical line holding \n sequences.
        return "\\n" in text and "\n" not in text

    escapes = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}

    def unescape(text):
        # Undo one level of JSON escaping. Invalid escapes such as "\ " stay as literal
        # text instead of raising "Invalid \escape" the way json.loads does.
        return re.sub(
            r'\\(u[0-9a-fA-F]{4}|["\\/bfnrt])',
            lambda m: chr(int(m.group(1)[1:], 16)) if len(m.group(1)) == 5 else escapes[m.group(1)],
            text,
        )

    source = kwargs.get("description")
    if source is None:
        # Input named something else in the editor (e.g. Detailed_Decription): use that one.
        source = next((v for k, v in kwargs.items() if k != "max_length" and v is not None), None)
    text = to_text(source)

    # Decode text that arrives already JSON-escaped - possibly wrapped in quotes or
    # escaped twice - so it ends up escaped exactly once below.
    for _ in range(3):
        stripped = text.strip()
        if len(stripped) >= 2 and stripped[0] == stripped[-1] == '"' and looks_escaped(stripped[1:-1]):
            text = unescape(stripped[1:-1])
        elif looks_escaped(text):
            text = unescape(text)
        else:
            break

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # \ud83c\uddfa-style escapes leave surrogate halves: join the pairs, drop strays below.
    text = text.encode("utf-16", "surrogatepass").decode("utf-16", "replace")

    # Pasted screenshots: ![](data:image/...) - also with line breaks between ] and ( -
    # <img src="data:...">, bare data:...;base64,... blobs, and an empty ![]() left behind.
    data_uri = r"data:[\w.+-]+/[\w.+-]+(?:;[\w.+-]+=[\w.+-]+)*;base64,[A-Za-z0-9+/=%]*"
    embedded = re.compile(
        r"(\s*)(?:"
        r"!\[[^\]\n]*\]\s*\(\s*<?" + data_uri + r">?\s*\)"
        r"|<img\b[^>]*?" + data_uri + r"[^>]*>"
        r"|" + data_uri +
        r"|!\[\](?:\s*\(\s*\))?"
        r")(\s*)",
        re.IGNORECASE,
    )

    def drop(match):
        if match.start() == 0 or match.end() == len(match.string):
            return ""
        gap = match.group(1) + match.group(2)
        return "\n" if "\n" in gap else (" " if gap else "")

    text = embedded.sub(drop, text)

    # Flag emoji are pairs of regional-indicator letters: keep them as the country code.
    text = re.sub("[\U0001F1E6-\U0001F1FF]", lambda m: chr(ord(m.group(0)) - 0x1F1E6 + ord("A")), text)
    text = text.translate({
        0x00A0: " ", 0x2007: " ", 0x202F: " ", 0x2028: "\n", 0x2029: "\n",
        0x2010: "-", 0x2011: "-", 0x2012: "-", 0x2013: "-", 0x2014: "-", 0x2015: "-", 0x2212: "-",
        0x2018: "'", 0x2019: "'", 0x201A: "'", 0x201B: "'",
        0x201C: '"', 0x201D: '"', 0x201E: '"', 0x201F: '"',
        0x2022: "-", 0x2026: "...", 0x2260: "!=", 0x2264: "<=", 0x2265: ">=",
    })
    # Other emoji (outside the Basic Multilingual Plane), invisible characters, and
    # control characters except \n and \t.
    text = re.sub(
        r"[\U00010000-\U0010FFFF\u00ad\u200b-\u200d\u2060\ufe0e\ufe0f\ufeff\ufffd"
        r"\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]",
        "",
        text,
    ).strip()

    try:
        max_length = int(to_text(kwargs.get("max_length")).strip() or 0)
    except ValueError:
        max_length = 0
    if 0 < max_length < len(text):
        text = text[: max_length - 3].rstrip() + "..." if max_length > 3 else text[:max_length]

    outputs["description"] = json.dumps(text)[1:-1]  # escaped once; outer quotes dropped for your "..." slot
    outputs["description_plain"] = text

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
    ################################################################################
    ## Custom Code Goes Above This Line
    ################################################################################


def custom_function_body():
    """The exact block to paste between SOAR's "Custom Code" markers, read from the function above."""
    lines = inspect.getsource(sanitize_description).splitlines()
    start = next(i for i, line in enumerate(lines) if "Custom Code Goes Below This Line" in line) + 2
    end = next(i for i, line in enumerate(lines) if "Custom Code Goes Above This Line" in line) - 1
    return "\n".join(lines[start:end]).strip("\n") + "\n"


CUSTOM_FUNCTION_BODY = custom_function_body()


if __name__ == "__main__":
    if "--body" in sys.argv[1:]:
        print(CUSTOM_FUNCTION_BODY, end="")
        sys.exit(0)

    samples = {
        "raw text with quotes and line breaks": 'The file "report (2).pdf" was uploaded.\nPlease review.\n',
        "already escaped, with invalid \\ escapes": r'Logs: - \"request=\"GET / hXXp/1[.]1\ \ Host: www[.]example[.]com\"',
        "already escaped, with a pasted screenshot": (
            r'Detailed analysis: - \"Country \ud83c\uddfa\ud83c\uddf8 United States ![]'
            + "\n\n(data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==)\n\n"
            + r'\"\nRecommendations: - \"Block it.\"'
        ),
    }

    for label, sample in samples.items():
        try:
            json.loads('{"Detailed_Decription": "%s"}' % sample)
            before = "parses"
        except json.JSONDecodeError as exc:
            before = f"fails - {exc}"

        result = sanitize_description(description=sample)
        payload = json.loads('{"Detailed_Decription": "%s"}' % result["description"])

        print(label)
        print(f"  as-is in the JSON template : {before}")
        print(f"  after sanitize_description : parses -> {payload['Detailed_Decription']!r}\n")
