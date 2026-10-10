"""
Splunk SOAR "Custom Functions" library entry (Administration > Custom
Functions > New Custom Function - the /custom_function/ editor, **kwargs
signature, plain `return outputs` dict).

Use this INSTEAD of a JSON-escaping sanitizer whenever the block you feed
the output into (a Format block, or a REST Call action's JSON-typed body
field) already escapes the values it substitutes in. Escaping twice is what
produced the corrupted text you saw:

    {"Detailed_Decription": "\"Hi Team,\\n\\n...\\n\\n\""}

instead of the expected:

    {"Detailed_Decription": "Hi Team,\n\n..."}

That happens when an already-escaped string (quotes and all) gets escaped a
second time downstream. The fix is to output CLEAN, UNESCAPED plain text
here and let the one downstream JSON-building step do the only escaping
pass.

Editor setup (left panel):
  Name              : clean_description (or any name you like)
  Add Input         : Name = description   | Data Type = string
  Add Output (Item) : Name = description   | Data Type = string
                       (the output Name must match the key you set on
                       `outputs` below)

Paste everything from "import json" down to "return outputs" into the
editor, below the locked "Custom Code Goes Below This Line" marker.
"""

import json


def clean_description(**kwargs):
    """
    Returns a JSON-serializable object that implements the configured data paths:
    """

    ################################################################################
    ## Custom Code Goes Below This Line
    ################################################################################

    outputs = {}

    description = kwargs.get("description")
    text = "" if description is None else str(description)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    outputs["description"] = text

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
    ################################################################################
    ## Custom Code Goes Above This Line
    ################################################################################


if __name__ == "__main__":
    sample = 'Hi Team,\n\nThe file "report (2).pdf" was uploaded.\nPlease review.\n'

    result = clean_description(description=sample)
    print("Plain output (feed this straight to the next task):")
    print(repr(result["description"]))

    # This is the ONE place JSON escaping should happen - in the block that
    # actually builds the outgoing payload, done exactly once.
    payload = {"Detailed_Decription": result["description"]}
    print("\nFinal payload, escaped exactly once:")
    print(json.dumps(payload, indent=2))
