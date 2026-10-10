"""
Splunk SOAR "Custom Functions" library entry (Administration > Custom
Functions > New Custom Function - the /custom_function/ editor, Python 3.13
stub with a bare **kwargs signature and a plain `return outputs` dict).

Fixes the "Expecting ',' delimiter" / "Invalid control character" errors you
get when a multi-line or quote-containing description is dropped straight
into a JSON field (e.g. Detailed_Decription in a REST payload): a raw
newline or an unescaped " breaks the JSON the moment it lands inside a
string literal. This escapes those characters so the result is still a
plain string you can drop straight into your existing template - not a JSON
object, no extra wrapping quotes added.

Editor setup (left panel):
  Name              : sanitize_description (or any name you like)
  Add Input         : Name = description   | Data Type = string
  Add Output (Item) : Name = description   | Data Type = string
                       (the output Name must match the key you set on
                       `outputs` below)

Only the code between the "Custom Code Goes Below This Line" markers is
editable in SOAR's editor - the exact block to paste there is reproduced in
CUSTOM_FUNCTION_BODY below and demonstrated by sanitize_description() so it
can be tested here with plain `python3 splunk_soar_sanitize_description_cf.py`.
"""

import json


def sanitize_description(**kwargs):
    """
    Returns a JSON-serializable object that implements the configured data paths:
    """

    ################################################################################
    ## Custom Code Goes Below This Line
    ################################################################################

    outputs = {}

    description = kwargs.get("description")

    if description is None:
        sanitized = ""
    else:
        text = str(description).replace("\r\n", "\n").replace("\r", "\n")
        sanitized = json.dumps(text)[1:-1]  # escape \n, ", \ ; drop the outer quotes json.dumps adds

    outputs["description"] = sanitized

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
    ################################################################################
    ## Custom Code Goes Above This Line
    ################################################################################


CUSTOM_FUNCTION_BODY = '''\
    outputs = {}

    description = kwargs.get("description")

    if description is None:
        sanitized = ""
    else:
        text = str(description).replace("\\r\\n", "\\n").replace("\\r", "\\n")
        sanitized = json.dumps(text)[1:-1]  # escape \\n, ", \\ ; drop the outer quotes json.dumps adds

    outputs["description"] = sanitized

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
'''


if __name__ == "__main__":
    sample = 'The file "report (2).pdf" was uploaded.\nPlease review.\n'

    broken_payload = '{"Detailed_Decription": "%s"}' % sample
    try:
        json.loads(broken_payload)
    except json.JSONDecodeError as exc:
        print(f"Without sanitizing, embedding it in JSON fails: {exc}")

    result = sanitize_description(description=sample)
    print("\nOutput dict (what SOAR wires to the 'description' data path):")
    print(result)

    fixed_payload = '{"Detailed_Decription": "%s"}' % result["description"]
    print("\nAfter sanitizing, the same JSON template parses fine:")
    print(json.loads(fixed_payload))
