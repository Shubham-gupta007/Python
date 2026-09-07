"""
Splunk SOAR Custom Function: sanitize free text (e.g. a Description /
Detailed_Decription value) so it can be embedded inside a JSON payload
without breaking it.

Why errors like "Expecting ',' delimiter" happen:
  A JSON string literal cannot contain a raw/unescaped newline, tab, double
  quote, or backslash. If a "format" block (or any string-template code)
  drops multi-line/quoted text straight into a JSON template like:
      {"Detailed_Decription": "%%description%%"}
  the moment the description contains a stray " it closes the JSON string
  early, so the parser expects a comma/brace next and fails with
  "Expecting ',' delimiter: line X column Y"; a literal newline instead
  produces "Invalid control character". Both are the same root cause -
  an unescaped special character landed inside a JSON string literal.

Fix: escape those characters first (turn a real newline into the two
characters \ and n, escape " and \, etc.) before the text goes into the
template. The result is still ordinary text - a plain string, not a JSON
object, no surrounding quotes added - so you drop it straight into the
"%%value%%" slot you already have, inside your own quotes.

Block setup:
  Input parameter  : description (string)
  Output parameter : output_description (string)
"""

import json

try:
    import phantom.rules as phantom  # available only inside SOAR's playbook runtime
except ImportError:
    phantom = None


def sanitize_for_json(text) -> str:
    """Escape text so it is safe to place inside an existing pair of JSON quotes."""
    if text is None:
        return ""
    text = str(text).replace("\r\n", "\n").replace("\r", "\n")
    # json.dumps() quotes+escapes the string; strip the outer quotes it adds
    # so the caller can drop the result straight into their own "..." slot.
    return json.dumps(text)[1:-1]


def custom_function(container=None, description=None, **kwargs):
    """
    SOAR Custom Function entry point.

    Input  : description - the raw text you want to put in a JSON field
             (e.g. Detailed_Decription), possibly containing newlines,
             quotes, or backslashes.
    Output : output_description - the same text with those characters
             escaped: safe to substitute into "...": "%%output_description%%"
             without causing a JSON delimiter error downstream.
    """
    if phantom:
        phantom.debug("sanitize_for_json custom_function() called")

    sanitized = sanitize_for_json(description)

    outputs = {"output_description": sanitized}

    if phantom:
        phantom.custom_function.set_output(**outputs)

    return outputs


if __name__ == "__main__":
    sample = (
        'Dear Team,\n\nWe observed an alert. The file "report (2).pdf" '
        'was uploaded from 94.204.125.24.\nPlease review.\n'
    )

    print("Raw description (what breaks JSON):")
    print(repr(sample))

    broken_payload = '{"Detailed_Decription": "%s"}' % sample
    try:
        json.loads(broken_payload)
        print("\nUnsanitized text unexpectedly parsed OK (unusual).")
    except json.JSONDecodeError as exc:
        print(f"\nWithout sanitizing, embedding it in JSON fails as expected: {exc}")

    result = custom_function(description=sample)
    print("\nSanitized output_description:")
    print(result["output_description"])

    fixed_payload = '{"Detailed_Decription": "%s"}' % result["output_description"]
    parsed = json.loads(fixed_payload)
    print("\nAfter sanitizing, the same JSON template parses fine:")
    print(parsed)

    # A description with an embedded quote but no newlines reproduces the
    # specific "Expecting ',' delimiter" error mentioned above.
    quote_only_sample = 'The file "report.pdf" was uploaded.'
    broken_quote_payload = '{"Detailed_Decription": "%s"}' % quote_only_sample
    try:
        json.loads(broken_quote_payload)
    except json.JSONDecodeError as exc:
        print(f"\nEmbedded quote alone reproduces: {exc}")

    quote_only_result = custom_function(description=quote_only_sample)
    fixed_quote_payload = '{"Detailed_Decription": "%s"}' % quote_only_result["output_description"]
    print("Sanitized + re-parsed:", json.loads(fixed_quote_payload))
