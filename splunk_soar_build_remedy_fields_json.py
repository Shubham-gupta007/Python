"""
Splunk SOAR "Custom Functions" library entry (Administration > Custom
Functions > New Custom Function - the /custom_function/ editor, **kwargs
signature, plain `return outputs` dict).

Fixes: "Error while converting string to dictionary. Error Message:
Expecting ':' delimiter: line 5 column 19 (char 113)" on the BMC Remedy
create_ticket action.

Root cause: that error is Python's json module failing to parse the whole
"fields" parameter string the Remedy action converts into a dictionary.
That string was likely built with a Format block that concatenates each
field as "key": "value" text - which breaks the moment any field's raw
value (typically Detailed_Decription) contains a real newline or an
unescaped ". A JSON string literal cannot contain either.

Fix: never hand-build that JSON text. Take every Remedy field as a plain,
UNESCAPED input (real newlines/quotes, exactly as extracted from the alert)
and let json.dumps() build + escape the ENTIRE fields object in one single
pass. One escaping pass, done correctly, everywhere - no manual escaping
anywhere in the pipeline.

Editor setup (left panel):
  Name              : build_remedy_fields_json (or any name you like)
  Add Input         : one input per Remedy field you need, e.g.
                       First_Name, Last_Name, "Internet E-mail", Description,
                       Detailed_Decription, Impact, Urgency, Status,
                       "Reported Source", Service_Type, "CRM SR Number",
                       "CRM TRN Number", "CRM Application/Bundle Number",
                       "Assigned Support Company",
                       "Assigned Support Organization", "Assigned Group",
                       z1D_Action - wire each straight from the CEF/artifact
                       values, no escaping needed on your end.
  Add Output (Item) : Name = fields_json   | Data Type = string

Then, on the create_ticket action, point its "fields" parameter at this
function's fields_json output instead of whatever Format block string was
there before.
"""

import json


def build_remedy_fields_json(**kwargs):
    """
    Returns a JSON-serializable object that implements the configured data paths:
    """

    ################################################################################
    ## Custom Code Goes Below This Line
    ################################################################################

    outputs = {}

    # Drop any input left empty/unset; keep every field the caller provided otherwise.
    fields = {key: value for key, value in kwargs.items() if value not in (None, "")}

    outputs["fields_json"] = json.dumps(fields)

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
    ################################################################################
    ## Custom Code Goes Above This Line
    ################################################################################


if __name__ == "__main__":
    detailed_description = (
        'Hi Team,\n\nSOC has observed an alert for the UC :\n'
        '9725_waf_critical_or_high_allowed_events_detected\n\n'
        'Uploaded PDF : URBAN OAK FURNITURE TRADING - L.L.C - S.P.C (2).pdf\n'
        '- The PDF appears to be a business document with "quoted" text.\n'
    )

    result = build_remedy_fields_json(
        First_Name="svc",
        Last_Name="soaritsmuat",
        **{"Internet E-mail": "svc.soaritsmuat@tax.gov.ae"},
        Description="BMC REST API: CRM Incident Creation Sample123",
        Detailed_Decription=detailed_description,
        Impact="3-Moderate/Limited",
        Urgency="3-Medium",
        Status="Assigned",
        **{"CRM SR Number": "SR_123"},
        z1D_Action="CREATE",
    )

    print("fields_json output (feed this straight to the create_ticket action):")
    print(result["fields_json"])

    print("\nRound-trip check - json.loads() succeeds on the whole thing:")
    print(json.loads(result["fields_json"]))
