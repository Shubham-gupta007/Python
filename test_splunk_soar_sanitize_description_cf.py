"""
Tests for splunk_soar_sanitize_description_cf.py.

Run with:  python3 -m unittest test_splunk_soar_sanitize_description_cf -v

The containers below are made-up data shaped like real production ones: one
whose ticket was created fine, and two that broke BMC Remedy ticket creation.
Custom fields are stored the way SOAR holds them: JSON string literals,
outer quotes included.
"""

import base64
import inspect
import json
import random
import re
import sys
import time
import unittest
from unittest import mock

from splunk_soar_sanitize_description_cf import custom_function_body, sanitize_description

SEPARATOR = "\n" + "*" * 76 + " \n"
US = "\N{REGIONAL INDICATOR SYMBOL LETTER U}\N{REGIONAL INDICATOR SYMBOL LETTER S}"
NL = "\N{REGIONAL INDICATOR SYMBOL LETTER N}\N{REGIONAL INDICATOR SYMBOL LETTER L}"
SCREENSHOT = base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 600).decode()


def literal(text):
    """How the custom fields store text: a JSON string literal, outer quotes included."""
    return json.dumps(text)


def container(analysis="", recommendations="", description="", logs="", soar_id="1234567",
              name="SOC Alert | 9405__user-added-to-security-enabled-group__sp2 | medium", wrap=literal):
    return {
        "id": 101,
        "name": name,
        "custom_fields": {
            "CPX SOAR ID": soar_id,
            "Detailed Analysis": wrap(analysis),
            "Recommendations": wrap(recommendations),
            "Description": wrap(description),
            "Logs": wrap(logs),
        },
    }


WORKING = container(
    analysis="Hi Team, SOC has observed multiple alerts.\nSource hosts: DC01.EXAMPLE.COM, 192.0.2.10\n"
             "admin-user1 | user.one | 4728 | GRP-Example-RO ",
    recommendations="Please verify and confirm whether this activity was expected. ",
    description='1792578629, search_name="Threat - 9405 - Rule", contributing_events_search="| savedsearch '
                '\\"Threat - 9405 - Rule\\" | search src_user=\\"admin-user1\\"", user="user[.]one"',
    logs="LogName=Security<br>EventCode=4728<br>Subject:<br>\tSecurity ID:\t\tEXAMPLE\\admin-user1"
         "<br>\tPrivileges:\t\t-",
)

# Escaped CRLFs inside F5 log lines (one and two escaping levels), a raw flag emoji, <= and an en dash:
# the previous version left "\ \ " behind and Remedy failed with "Invalid \escape".
WP2SHELL = container(
    name="SOC Alert | 8012_CVE-2026-6303 -wp2shell - Pre-Authentication RCE in WordPress Core | high",
    analysis=f"Dear Team, CPX SOC has detected an alert for 8012_wp2shell.\nSource IP | 203.0.113.40\n"
             f"Country {NL} Netherlands",
    recommendations="Confirm whether www[.]example[.]com hosts WordPress. ",
    description='orig_raw="<134>Oct 20 waf01[.]example[.]com ASM:request=\\"GET /ar/default[.]aspx hXXp/1[.]1'
                '\\\\r\\\\nHost: www[.]example[.]com\\\\r\\\\n\\\\r\\\\n\\",response=\\"Logging rate limit\\" ", '
                'orig_rule_description="Affected WordPress Versions \u2264 6[.]8[.]5: Not affected 6[.]9[.]0 '
                '\u2013 6[.]9[.]4: Affected"',
    logs='request="GET /ar/default[.]aspx hXXp/1[.]1\\r\\nHost: www[.]example[.]com\\r\\n'
         'X-Forwarded-For: 203[.]0[.]113[.]40\\r\\n\\r\\n",response="Logging rate limit reached"',
)

# A pasted screenshot and a flag emoji (stored escaped, the way json.dumps writes it).
SCREENSHOT_CONTAINER = container(
    name="SOC Alert | Fortigate Horizantal Port Scan Perimeter UCSC | medium",
    analysis=f"Dear Team,\nSource IP: 198.51.100.213\nCountry {US} United States of America\n"
             f"The most recent report was 2 minutes ago. ![](data:image/png;base64,{SCREENSHOT})",
    recommendations="Block or deny-list 198[.]51[.]100[.]213 at the perimeter. ",
    description='search_name="Threat - Fortigate Horizantal Port Scan - Rule", srcip="198[.]51[.]100[.]213"',
    logs='date=2026-10-19 devname="fw01" srcip=198[.]51[.]100[.]213 action="client-rst"<br>',
)

SHAPES = {"working": WORKING, "wp2shell": WP2SHELL, "screenshot": SCREENSHOT_CONTAINER}

REMEDY_TEMPLATE = """{
"First_Name": "svc",
"Last_Name": "soaritsm",
"Description": "%s",
"Detailed_Decription": "%s",
"Impact": "3-Moderate/Limited",
"Urgency": "3-Medium",
"Status": "Assigned",
"z1D_Action": "CREATE"
}"""


def run(container_object, container_id=101):
    with mock.patch.object(sys.modules["phantom.rules"], "get_container", return_value=container_object) as get:
        result = sanitize_description(container_id=container_id)
    return result, get


def remedy(result):
    """What the BMC Remedy create-ticket action parses out of the Format block's JSON."""
    return json.loads(REMEDY_TEMPLATE % (result["description"], result["detailed_description"]))


def sections(result):
    parts = remedy(result)["Detailed_Decription"].split(SEPARATOR)
    return dict(part.split(" - ", 1) for part in parts)


def previous_version(container_object):
    """The section and summary logic of the version this replaced, kept to compare outputs."""
    ip_pattern = re.compile(r"\b\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3}(?:\[\.\]|\.)\d{1,3}\b")
    fields = container_object["custom_fields"]
    lines = []
    for label, key in (("Detailed analysis:", "Detailed Analysis"), ("Recommendations:", "Recommendations"),
                       ("Description:", "Description"), ("Logs:", "Logs")):
        value = fields.get(key)
        text = "" if value is None else str(value)
        text = text.replace("\\r\\n", " ").replace("\\n", " ").replace("\\r", " ")
        text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
        text = " ".join(text.split())
        if label == "Detailed analysis:":
            text = ip_pattern.sub(lambda m: "\\n" + m.group(0), text).replace("[.]", ".")
        text = re.sub(r'(?<!\\)"', '\\"', text)
        lines.append(f"{label} - {text}")
    parts = [p.strip() for p in container_object["name"].split("|")]
    summary = "CPX | ID: " + str(fields.get("CPX SOAR ID")) + " | " + (parts[1] if len(parts) > 1 else container_object["name"])
    return {
        "detailed_description": ("\\n" + "*" * 76 + " \\n").join(lines),
        "description": json.dumps(summary)[1:-1],
    }


class ProductionShapes(unittest.TestCase):
    def test_unchanged_where_the_previous_version_worked(self):
        result, _ = run(WORKING)
        self.assertEqual(result, previous_version(WORKING))

    def test_previous_version_broke_on_escaped_crlf(self):
        with self.assertRaisesRegex(json.JSONDecodeError, r"Invalid \\escape"):
            remedy(previous_version(WP2SHELL))

    def test_every_shape_builds_a_valid_ascii_remedy_payload(self):
        for name, shape in SHAPES.items():
            with self.subTest(name):
                result, _ = run(shape)
                payload = remedy(result)
                self.assertEqual(payload["z1D_Action"], "CREATE")
                self.assertTrue((result["description"] + result["detailed_description"]).isascii())
                self.assertEqual(list(sections(result)), ["Detailed analysis:", "Recommendations:", "Description:", "Logs:"])

    def test_escaped_crlf_in_logs_becomes_a_space(self):
        result, _ = run(WP2SHELL)
        found = sections(result)
        self.assertIn("hXXp/1[.]1 Host: www[.]example[.]com X-Forwarded-For: 203[.]0[.]113[.]40", found["Logs:"])
        self.assertIn('request=\\"GET /ar/default[.]aspx hXXp/1[.]1 Host: www[.]example[.]com', found["Description:"])
        self.assertNotIn("\\ ", remedy(result)["Detailed_Decription"])

    def test_wp2shell_characters(self):
        found = sections(run(WP2SHELL)[0])
        self.assertIn("Country NL Netherlands", found["Detailed analysis:"])
        self.assertIn("Versions <= 6[.]8[.]5: Not affected 6[.]9[.]0 - 6[.]9[.]4", found["Description:"])

    def test_screenshot_is_dropped(self):
        result, _ = run(SCREENSHOT_CONTAINER)
        analysis = sections(result)["Detailed analysis:"]
        self.assertNotIn("data:image", analysis)
        self.assertNotIn(SCREENSHOT[:40], analysis)
        self.assertTrue(analysis.endswith('2 minutes ago. "'), analysis[-40:])
        self.assertIn("Country US United States of America", analysis)
        self.assertLess(len(result["detailed_description"]), 1500)

    def test_layout(self):
        found = sections(run(WORKING)[0])
        self.assertEqual(
            found["Detailed analysis:"],
            '"Hi Team, SOC has observed multiple alerts. Source hosts: DC01.EXAMPLE.COM, \n192.0.2.10 '
            'admin-user1 | user.one | 4728 | GRP-Example-RO "',
        )
        self.assertEqual(found["Recommendations:"], '"Please verify and confirm whether this activity was expected. "')
        self.assertIn('contributing_events_search="| savedsearch \\"Threat - 9405 - Rule\\"', found["Description:"])
        self.assertEqual(found["Logs:"], '"LogName=Security<br>EventCode=4728<br>Subject:<br>\tSecurity ID:\t\t'
                                         'EXAMPLE\\admin-user1<br>\tPrivileges:\t\t-"')


class DetailedAnalysis(unittest.TestCase):
    def test_each_ip_starts_a_line_and_defanged_dots_are_restored(self):
        analysis = sections(run(container(analysis="Seen from 192[.]0[.]2[.]1 and 198.51.100.2 today"))[0])
        self.assertEqual(analysis["Detailed analysis:"], '"Seen from \n192.0.2.1 and \n198.51.100.2 today"')

    def test_other_sections_keep_defanged_values(self):
        found = sections(run(container(recommendations="Block 192[.]0[.]2[.]1"))[0])
        self.assertEqual(found["Recommendations:"], '"Block 192[.]0[.]2[.]1"')


class Backslashes(unittest.TestCase):
    def test_backslashes_survive(self):
        logs = "user=EXAMPLE\\nasser path=C:\\temp\\run.exe share=\\\\srv\\c$ trailing\\"
        result, _ = run(container(logs=logs))
        self.assertEqual(sections(result)["Logs:"], '"' + logs + '"')

    def test_previous_version_broke_on_them(self):
        with self.assertRaises(json.JSONDecodeError):
            remedy(previous_version(container(logs="user=EXAMPLE\\nasser")))

    def test_decoded_only_once(self):
        for logs in ("EXAMPLE\\nasser", "C:\\temp\\new", "a\\\\b", 'say \\"hi\\"'):
            with self.subTest(logs=logs):
                self.assertEqual(sections(run(container(logs=logs))[0])["Logs:"], '"' + logs + '"')

    def test_crlf_at_any_escaping_depth(self):
        for crlf in ("\\r\\n", "\\\\r\\\\n", "\\\\\\r\\\\\\n"):
            with self.subTest(crlf=crlf):
                self.assertEqual(sections(run(container(logs=f"a{crlf}b"))[0])["Logs:"], '"a b"')


class Summary(unittest.TestCase):
    def description(self, **kwargs):
        return remedy(run(container(**kwargs))[0])["Description"]

    def test_use_case_from_the_container_name(self):
        self.assertEqual(self.description(name="SOC Alert | 9405_rule | medium"), "CPX | ID: 1234567 | 9405_rule")
        self.assertEqual(self.description(name="Just a name"), "CPX | ID: 1234567 | Just a name")

    def test_quotes_and_emoji_in_the_name(self):
        self.assertEqual(self.description(name=f'A | Rule "x" {US} | b'), 'CPX | ID: 1234567 | Rule "x" US')

    def test_cut_to_remedys_100_characters(self):
        text = self.description(name="A | " + "very long use case name " * 10 + "| b")
        self.assertLessEqual(len(text), 100)
        self.assertEqual(text, ("CPX | ID: 1234567 | " + "very long use case name " * 10)[:97].rstrip() + "...")
        exact = "x" * 80  # "CPX | ID: 1234567 | " is 20 characters
        self.assertEqual(self.description(name=f"A | {exact} | b"), "CPX | ID: 1234567 | " + exact)

    def test_cpx_soar_id_forms(self):
        self.assertEqual(self.description(soar_id=7654321, name="Rule"), "CPX | ID: 7654321 | Rule")
        self.assertEqual(self.description(soar_id='"7654321"', name="Rule"), "CPX | ID: 7654321 | Rule")
        self.assertEqual(self.description(soar_id=None, name="Rule"), "CPX | ID: None | Rule")  # as before


class ContainerInput(unittest.TestCase):
    def test_container_id_shapes(self):
        for value in (101, "101", " 101 ", [101], ["101"], [[None, 101]], [None, "", 101]):
            with self.subTest(value=value):
                _, get = run(WORKING, container_id=value)
                get.assert_called_once_with(101)

    def test_no_container(self):
        for value in (None, "", [], [None]):
            with self.subTest(value=value):
                result, get = run(WORKING, container_id=value)
                get.assert_not_called()
                self.assertEqual(result, {"detailed_description": None, "description": None})
        result, _ = run(None)
        self.assertEqual(result, {"detailed_description": None, "description": None})  # was "ul" before

    def test_custom_field_name_variants(self):
        shape = container(analysis="text A", logs="text L")
        for style in (str.lower, str.upper, lambda key: key.replace(" ", "_"), lambda key: key.lower().replace(" ", "_")):
            with self.subTest(style=style):
                renamed = dict(shape, custom_fields={style(k): v for k, v in shape["custom_fields"].items()})
                found = sections(run(renamed)[0])
                self.assertEqual((found["Detailed analysis:"], found["Logs:"]), ('"text A"', '"text L"'))

    def test_missing_and_empty_custom_fields(self):
        for fields in (None, {}, {"Detailed Analysis": None}):
            with self.subTest(fields=fields):
                result, _ = run({"name": "A | Rule | b", "custom_fields": fields})
                self.assertEqual(remedy(result)["Detailed_Decription"], SEPARATOR.join(
                    f"{label} - " for label in ("Detailed analysis:", "Recommendations:", "Description:", "Logs:")))
                self.assertEqual(remedy(result)["Description"], "CPX | ID: None | Rule")

    def test_plain_text_fields_are_not_wrapped_in_quotes(self):
        shape = container(analysis='He said "hi"\nnext line', logs="a\tb", wrap=lambda text: text)
        found = sections(run(shape)[0])
        self.assertEqual(found["Detailed analysis:"], 'He said "hi" next line')
        self.assertEqual(found["Logs:"], "a\tb")

    def test_list_valued_field(self):
        shape = container()
        shape["custom_fields"]["Logs"] = ["first", "second"]
        self.assertEqual(sections(run(shape)[0])["Logs:"], "first second")


class Characters(unittest.TestCase):
    def logs(self, text, wrap=literal):
        return sections(run(container(logs=text, wrap=wrap))[0])["Logs:"]

    def test_flags_emoji_and_typography(self):
        self.assertEqual(self.logs(f"{US} \N{POLICE CARS REVOLVING LIGHT} \u201cq\u201d \u2018s\u2019 \u2026 \u2022 \u2265"),
                         "\"US \"q\" 's' ... - >=\"")

    def test_stray_surrogate_escape_is_dropped(self):
        self.assertEqual(self.logs('"x ' + "\\" + 'ud83c y"', wrap=lambda text: text), '"x y"')

    def test_invisible_and_control_characters(self):
        # \x85 (next line) and \x1c are line breaks: they become a space like \n does.
        self.assertEqual(self.logs("a\x00b\x1bc\u200bd\ufeffe\u00adf\x85g\x1ch"), '"abcdef g h"')

    def test_non_latin_letters_kept(self):
        text = "\u0645\u0631\u062d\u0628\u0627 caf\u00e9 \u6f22\u5b57"
        result, _ = run(container(logs=text))
        self.assertTrue(result["detailed_description"].isascii())
        self.assertEqual(sections(result)["Logs:"], '"' + text + '"')


class EmbeddedImages(unittest.TestCase):
    def analysis(self, text, wrap=literal):
        return sections(run(container(analysis=text, wrap=wrap))[0])["Detailed analysis:"]

    def test_forms(self):
        for text in (
            "a ![shot](data:image/png;base64,iVBORw0KGgo=) b",
            "a ![]\n\n(data:image/jpeg;base64,/9j/4AAQ+/=)\n\n b",
            'a <img alt="x" src="data:image/gif;base64,R0lGODlh"/> b',
            "a DATA:IMAGE/PNG;BASE64,iVBORw0KGgo= b",
            "a data:image/svg+xml;charset=utf-8;base64,PHN2Zz4= b",
        ):
            with self.subTest(text=text[:30]):
                self.assertEqual(self.analysis(text), '"a b"')

    def test_real_line_breaks_inside_the_stored_literal(self):
        stored = literal("Seen 2 minutes ago.")[:-1] + " ![]\n\n(data:image/png;base64," + SCREENSHOT + ")\n\n" + '"'
        self.assertEqual(self.analysis(stored, wrap=lambda text: text), '"Seen 2 minutes ago. "')

    def test_links_and_words_are_kept(self):
        text = "data: image/png is fine, see https://example.com/a(b) and ![logo](https://example.com/x.png)"
        self.assertEqual(self.analysis(text), '"' + text + '"')

    def test_large_screenshot_is_fast(self):
        blob = base64.b64encode(bytes(3_000_000)).decode()  # 4 MB of base64
        started = time.perf_counter()
        found = self.analysis(f"start ![](data:image/png;base64,{blob}) end")
        self.assertLess(time.perf_counter() - started, 2)
        self.assertEqual(found, '"start end"')


class Fuzz(unittest.TestCase):
    PIECES = [
        '"', "\\", "\\\\", '\\"', "\\n", "\\r\\n", "\\t", "\\u", "\\" + "ud83c", "\\ ", "n", "r", "t", "a", "Z", "0",
        " ", "\n", "\r\n", "\t", "\x00", "\x1f", US, "\N{GRINNING FACE}", "\ud83c", "\u00e9", "\u0645", "\u2013",
        "{", "}", ",", ":", "|", "[.]", "192.0.2.1", "<br>", "![](data:image/png;base64,QUJD)", "base64,", "/",
    ]

    def test_random_fields_always_give_a_valid_ascii_payload(self):
        rng = random.Random(20261021)
        for _ in range(1500):
            values = ["".join(rng.choice(self.PIECES) for _ in range(rng.randint(0, 30))) for _ in range(6)]
            wrap = literal if rng.random() < 0.6 else (lambda text: text)
            shape = container(*map(wrap, values[:4]), soar_id=values[4], name=values[5], wrap=lambda text: text)
            result, _ = run(shape)
            try:
                payload = remedy(result)
            except json.JSONDecodeError as exc:  # pragma: no cover - failure path
                self.fail(f"{values!r}: {exc}")
            text = payload["Detailed_Decription"] + payload["Description"]
            self.assertTrue((result["description"] + result["detailed_description"]).isascii(), values)
            self.assertLessEqual(len(payload["Description"]), 100)
            self.assertFalse(any(ord(c) < 32 and c not in "\n\t" for c in text), values)
            self.assertFalse(any(ord(c) > 0xFFFF or 0xD800 <= ord(c) <= 0xDFFF for c in text), values)
            self.assertNotIn("data:image", text.lower(), values)


class PasteBlock(unittest.TestCase):
    """The block pasted under the editor's marker, run under the def line SOAR generates."""

    BODY = custom_function_body()
    HEADER = "def sanitize_description(container_id=None, **kwargs):\n" \
             "    ############################ Custom Code Goes Below This Line #################################\n"

    def pasted(self, prefix=""):
        namespace = {}  # no module-level imports: the block has to bring its own
        exec(self.HEADER + prefix + self.BODY, namespace)
        return namespace["sanitize_description"]

    def test_block_shape(self):
        self.assertTrue(self.BODY.isascii())
        self.assertNotIn("\t", self.BODY)
        self.assertTrue(self.BODY.startswith("    import json\n"))
        self.assertTrue(self.BODY.rstrip().endswith("return outputs"))
        self.assertIn(self.HEADER.splitlines()[1], inspect.getsource(sanitize_description))

    def test_same_results_under_the_generated_header(self):
        for prefix in ("", "    import json\n    import phantom.rules as phantom\n    import re\n\n"):
            fn = self.pasted(prefix)
            for name, shape in SHAPES.items():
                with self.subTest(name, prefix=bool(prefix)):
                    with mock.patch.object(sys.modules["phantom.rules"], "get_container", return_value=shape):
                        self.assertEqual(fn(container_id=[101]), run(shape)[0])

    def test_debug_lines(self):
        with mock.patch.object(sys.modules["phantom.rules"], "debug") as debug:
            run(WORKING)
        messages = [call.args[0] for call in debug.call_args_list]
        self.assertEqual([m.split(":")[0] for m in messages], ["c_id found", "description found", "detailed_description found"])


if __name__ == "__main__":
    unittest.main()
