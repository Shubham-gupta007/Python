"""
Tests for splunk_soar_sanitize_description_cf.py.

Run with:  python3 -m unittest test_splunk_soar_sanitize_description_cf -v

The three *_SHAPED samples reproduce, with made-up data, the structure of
real Detailed_Decription values seen in production: one that already
worked and two that broke BMC Remedy ticket creation.
"""

import base64
import inspect
import json
import random
import sys
import time
import unittest
from unittest import mock

from splunk_soar_build_remedy_fields_json import build_remedy_fields_json
from splunk_soar_sanitize_description_cf import custom_function_body, sanitize_description

# Already escaped with valid escapes only (\" \n \t \\) - this shape always worked.
WORKING_SHAPED = (
    r'Detailed analysis: - \"Hi Team, SOC has observed multiple alerts for the UC : '
    r'9405__user-added-to-security-enabled-group src_user | Added User | Group_Name ---|---|--- '
    r'admin-user1 | user.one | GRP-Example-RO \"\n'
    r'**************************************************************************** \nRecommendations: - '
    r'\"Please verify and confirm whether this activity was expected. \"\n'
    r'**************************************************************************** \nDescription: - '
    r'\"search_name=\"Threat - 9405 - Rule\", contributing_events_search=\"| savedsearch '
    r'\\\"Threat - 9405 - Rule\\\" | search src_user=\\\"admin-user1\\\"\", user=\"user[.]one\"\"\n'
    r'**************************************************************************** \nLogs: - '
    r'\"LogName=Security<br>EventCode=4728<br>Subject:<br>\tSecurity ID:\t\tEXAMPLE\\admin-user1'
    r'<br>\tPrivileges:\t\t-\"'
)

# Already escaped, but with invalid "\ " escapes, a raw flag emoji, and <= / en dash:
# json.loads fails with "Invalid \escape".
INVALID_ESCAPE_SHAPED = (
    r'Detailed analysis: - \"Dear Team, CPX SOC has detected an alert for 8012_wp2shell. '
    r'Source IP | \n203.0.113.40 Country 🇳🇱 Netherlands \"\n'
    r'**************************************************************************** \nDescription: - '
    r'\"orig_raw=\"<134>Oct 20 01:26:33 waf01[.]example[.]com ASM:unit_hostname=\\\"waf01[.]example[.]com\\\",'
    r'request=\\\"GET /ar/default[.]aspx?rest_route=/batch/v1 hXXp/1[.]1\\\ \\\ Host: www[.]example[.]com'
    r'\\\ \\\ \\\",response=\\\"Logging rate limit reached\\\" \", orig_rule_description=\"Affected '
    r'WordPress Versions ≤ 6[.]8[.]5: Not affected 6[.]9[.]0 – 6[.]9[.]4: Affected\"\"\n'
    r'**************************************************************************** \nLogs: - '
    r'\"request=\"GET /ar/default[.]aspx hXXp/1[.]1\ \ Host: www[.]example[.]com\ \ '
    r'X-Forwarded-For: 203[.]0[.]113[.]40\ \ \ \ \",response=\"Logging rate limit reached\"\"'
)

# Already escaped, with real line breaks around a pasted screenshot and a
# \ud83c\uddfa\ud83c\uddf8 flag escape: json.loads fails with "Invalid control character".
SCREENSHOT = base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 600).decode()
SCREENSHOT_SHAPED = (
    r'Detailed analysis: - \"Dear Team, CPX SOC has detected an alert for Fortigate Horizontal Port Scan. '
    r'Source IP: \n198.51.100.213 Country \ud83c\uddfa\ud83c\uddf8 United States of America. This IP '
    r'address has been reported 1,521 times, the most recent report was 2 minutes ago. ![]'
    "\n\n(data:image/png;base64," + SCREENSHOT + ")\n\n"
    r'\"\n**************************************************************************** \nRecommendations: '
    r'- \"Block or deny-list 198[.]51[.]100[.]213 at the perimeter. \"\n'
    r'**************************************************************************** \nLogs: - '
    r'\"date=2026-10-19 devname=\"fw01\" srcip=198[.]51[.]100[.]213 action=\"client-rst\"<br>\"'
)

SHAPED = {"working": WORKING_SHAPED, "invalid escape": INVALID_ESCAPE_SHAPED, "screenshot": SCREENSHOT_SHAPED}

REMEDY_TEMPLATE = """{
"First_Name": "svc",
"Last_Name": "soaritsm",
"Description": "CPX | ID: 1234567 | test",
"Detailed_Decription": "%s",
"Impact": "3-Moderate/Limited",
"Urgency": "3-Medium",
"Status": "Assigned",
"z1D_Action": "CREATE"
}"""


def sanitize(description, **extra):
    return sanitize_description(description=description, **extra)


def ticket_text(escaped):
    """What Remedy receives once the create-ticket action parses the Format block's JSON."""
    return json.loads(REMEDY_TEMPLATE % escaped)["Detailed_Decription"]


class ProductionShapes(unittest.TestCase):
    def test_broken_shapes_reproduce_the_original_errors(self):
        ticket_text(WORKING_SHAPED)
        with self.assertRaisesRegex(json.JSONDecodeError, r"Invalid \\escape"):
            ticket_text(INVALID_ESCAPE_SHAPED)
        with self.assertRaisesRegex(json.JSONDecodeError, "Invalid control character"):
            ticket_text(SCREENSHOT_SHAPED)

    def test_every_shape_builds_a_valid_remedy_payload(self):
        for name, sample in SHAPED.items():
            with self.subTest(name):
                escaped = sanitize(sample)["description"]
                payload = json.loads(REMEDY_TEMPLATE % escaped)
                self.assertEqual(payload["z1D_Action"], "CREATE")
                self.assertTrue(escaped.isascii())
                text = payload["Detailed_Decription"]
                self.assertTrue(text.startswith('Detailed analysis: - "'), text[:40])
                self.assertIn("****", text)

    def test_valid_escaped_text_is_decoded_not_escaped_twice(self):
        result = sanitize(WORKING_SHAPED)
        expected = json.loads('"%s"' % WORKING_SHAPED)
        self.assertEqual(result["description_plain"], expected)
        self.assertEqual(ticket_text(result["description"]), expected)
        self.assertIn('savedsearch \\"Threat - 9405 - Rule\\"', expected)  # nested level stays as-is
        self.assertIn("\tSecurity ID:\t\tEXAMPLE\\admin-user1", expected)

    def test_invalid_escapes_are_kept_as_literal_backslashes(self):
        text = ticket_text(sanitize(INVALID_ESCAPE_SHAPED)["description"])
        self.assertIn("hXXp/1[.]1\\ \\ Host: www[.]example[.]com", text)  # from "\ \ "
        self.assertIn("hXXp/1[.]1\\\\ \\\\ Host:", text)  # from "\\\ \\\ "
        self.assertIn('request=\\"GET /ar/default', text)
        self.assertIn("Country NL Netherlands", text)
        self.assertIn("Versions <= 6[.]8[.]5: Not affected 6[.]9[.]0 - 6[.]9[.]4", text)

    def test_screenshot_is_removed_and_surrounding_text_kept(self):
        result = sanitize(SCREENSHOT_SHAPED)
        text = ticket_text(result["description"])
        self.assertNotIn("data:image", text)
        self.assertNotIn(SCREENSHOT[:40], text)
        self.assertNotIn("![]", text)
        self.assertIn('2 minutes ago.\n"\n****', text)
        self.assertIn('Recommendations: - "Block or deny-list', text)
        self.assertIn("Country US United States of America", text)
        self.assertLess(len(result["description"]), 1500)

    def test_output_is_stable_when_fed_back_in(self):
        for name, sample in SHAPED.items():
            with self.subTest(name):
                first = sanitize(sample)
                self.assertEqual(sanitize(first["description"])["description"], first["description"])
                self.assertEqual(sanitize(first["description_plain"])["description"], first["description"])

    def test_plain_output_works_with_build_remedy_fields_json(self):
        for name, sample in SHAPED.items():
            with self.subTest(name):
                plain = sanitize(sample)["description_plain"]
                fields_json = build_remedy_fields_json(Detailed_Decription=plain, z1D_Action="CREATE")["fields_json"]
                self.assertEqual(json.loads(fields_json)["Detailed_Decription"], plain)


class RawText(unittest.TestCase):
    def test_raw_text_round_trips_exactly(self):
        raw = 'Hi Team,\n\nThe file "report (2).pdf" was uploaded.\n\tpath: C:\\temp\\new\nPlease review.'
        result = sanitize(raw)
        self.assertEqual(result["description_plain"], raw)
        self.assertEqual(ticket_text(result["description"]), raw)

    def test_backslashes_in_raw_text_are_not_treated_as_escapes(self):
        raw = 'Account "EXAMPLE\\nasser" ran C:\\tools\\run.exe \\u12 \\"'
        self.assertEqual(ticket_text(sanitize(raw)["description"]), raw)

    def test_quotes_and_braces_cannot_break_out_of_the_field(self):
        raw = '", "Status": "Closed", "x": {"y": "}'
        payload = json.loads(REMEDY_TEMPLATE % sanitize(raw)["description"])
        self.assertEqual(payload["Detailed_Decription"], raw)
        self.assertEqual(payload["Status"], "Assigned")


class EmbeddedImages(unittest.TestCase):
    def assert_removed(self, text, expected):
        result = sanitize(text)
        self.assertEqual(result["description_plain"], expected)
        self.assertEqual(ticket_text(result["description"]), expected)

    def test_markdown_image(self):
        self.assert_removed("before ![screenshot](data:image/png;base64,iVBORw0KGgo=) after", "before after")

    def test_markdown_image_with_line_breaks_between_brackets(self):
        self.assert_removed("before ![]\n\n(data:image/jpeg;base64,/9j/4AAQ+/=)\n\nafter", "before\nafter")

    def test_html_img_tag(self):
        self.assert_removed('a <img alt="x" src="data:image/gif;base64,R0lGODlh"/> b', "a b")

    def test_bare_data_uri_and_mixed_case(self):
        self.assert_removed("a DATA:IMAGE/PNG;BASE64,iVBORw0KGgo= b", "a b")
        self.assert_removed("a data:image/svg+xml;charset=utf-8;base64,PHN2Zz4= b", "a b")

    def test_image_at_start_or_end(self):
        self.assert_removed("![](data:image/png;base64,QUJD)\nText", "Text")
        self.assert_removed("Text ![](data:image/png;base64,QUJD)", "Text")

    def test_image_inside_escaped_text(self):
        escaped = r'\"Seen ![](data:image/png;base64,QUJD) twice\"\nnext'
        self.assertEqual(sanitize(escaped)["description_plain"], '"Seen twice"\nnext')

    def test_ordinary_words_and_links_are_kept(self):
        text = "data: image/png is fine, see https://example.com/a(b) and ![logo](https://example.com/x.png)"
        self.assert_removed(text, text)

    def test_large_screenshot_is_fast(self):
        blob = base64.b64encode(bytes(3_000_000)).decode()  # 4 MB of base64
        started = time.perf_counter()
        result = sanitize(r'\"start ![](data:image/png;base64,' + blob + r') end\"')
        self.assertLess(time.perf_counter() - started, 2)
        self.assertEqual(result["description_plain"], '"start end"')


class Characters(unittest.TestCase):
    def test_flag_emoji_become_country_codes(self):
        self.assertEqual(sanitize("Country 🇺🇸 USA")["description_plain"], "Country US USA")
        self.assertEqual(sanitize(r"\"Country \ud83c\uddf3\ud83c\uddf1\"")["description_plain"], '"Country NL"')

    def test_other_emoji_and_stray_surrogates_are_dropped(self):
        self.assertEqual(sanitize("alert🚨 raised 👍🏽")["description_plain"], "alert raised")
        self.assertEqual(sanitize(r"\"x \ud83c y\"")["description_plain"], '"x  y"')
        self.assertEqual(sanitize("x \ud83c y")["description_plain"], "x  y")

    def test_typographic_punctuation_becomes_ascii(self):
        text = "≤ 6.8.5 – 6.9.4 — “quoted” ‘single’ … • ≥ ≠\u00a0end"
        self.assertEqual(sanitize(text)["description_plain"], "<= 6.8.5 - 6.9.4 - \"quoted\" 'single' ... - >= != end")

    def test_control_and_invisible_characters_are_removed(self):
        text = "a\x00b\x1bc\u200bd\ufeffe\u00adf\x85g\r\nh\ri\u2028j\tk"
        self.assertEqual(sanitize(text)["description_plain"], "abcdefg\nh\ni\nj\tk")

    def test_non_latin_letters_are_kept(self):
        text = "Arabic: مرحبا بكم, accents: café, CJK: 漢字"
        result = sanitize(text)
        self.assertEqual(result["description_plain"], text)
        self.assertTrue(result["description"].isascii())
        self.assertEqual(ticket_text(result["description"]), text)


class InputShapes(unittest.TestCase):
    def test_empty_inputs(self):
        for value in (None, "", "   \n\t", [], [None, ""], b""):
            with self.subTest(value=value):
                self.assertEqual(sanitize(value), {"description": "", "description_plain": ""})

    def test_lists_from_soar_datapaths(self):
        self.assertEqual(sanitize(["one"])["description_plain"], "one")
        self.assertEqual(sanitize([["one"]])["description_plain"], "one")
        self.assertEqual(sanitize(("one",))["description_plain"], "one")
        self.assertEqual(sanitize(["one", None, "", ["two"]])["description_plain"], "one\ntwo")
        self.assertEqual(sanitize(["same", "same"])["description_plain"], "same")
        self.assertEqual(sanitize([WORKING_SHAPED])["description"], sanitize(WORKING_SHAPED)["description"])

    def test_bytes_and_numbers(self):
        self.assertEqual(sanitize("café".encode())["description_plain"], "café")
        self.assertEqual(sanitize(b"bad \xff byte")["description_plain"], "bad  byte")
        self.assertEqual(sanitize(12345)["description_plain"], "12345")

    def test_json_string_literals_and_double_escaping(self):
        plain = 'Hi Team,\n\n"quoted" text'
        self.assertEqual(sanitize(json.dumps(plain))["description_plain"], plain)
        self.assertEqual(sanitize(json.dumps(json.dumps(plain)))["description_plain"], plain)
        self.assertEqual(sanitize(r"Hi Team,\n\nsingle line, no quotes")["description_plain"], "Hi Team,\n\nsingle line, no quotes")

    def test_plain_quoted_text_is_not_unwrapped(self):
        self.assertEqual(sanitize('"just quoted"')["description_plain"], '"just quoted"')
        self.assertEqual(sanitize('"a" and "b"')["description_plain"], '"a" and "b"')

    def test_input_named_differently_in_the_editor(self):
        result = sanitize_description(Detailed_Decription='say "hi"')
        self.assertEqual(result["description_plain"], 'say "hi"')


class MaxLength(unittest.TestCase):
    def test_truncates_with_marker(self):
        result = sanitize('"quoted" ' * 50, max_length="100")
        self.assertEqual(len(result["description_plain"]), 100)
        self.assertTrue(result["description_plain"].endswith("..."))
        ticket_text(result["description"])

    def test_limit_counts_decoded_characters(self):
        result = sanitize(r"\"" + "a" * 200 + r"\"", max_length=50)
        self.assertEqual(len(result["description_plain"]), 50)

    def test_ignored_when_missing_invalid_or_large(self):
        for limit in (None, "", "abc", "0", "-5", 10_000, ["  "]):
            with self.subTest(limit=limit):
                self.assertEqual(sanitize("short text", max_length=limit)["description_plain"], "short text")

    def test_list_value_and_tiny_limits(self):
        self.assertEqual(sanitize("abcdefghij", max_length=["5"])["description_plain"], "ab...")
        self.assertEqual(sanitize("abcdefghij", max_length=3)["description_plain"], "abc")


class Fuzz(unittest.TestCase):
    PIECES = [
        '"', "\\", "\\\\", '\\"', "\\n", "\\t", "\\u", "\\ud83c", "\\uddfa", "\\u00e9", "\\ ", "\\x",
        "n", "t", "u", "d83c", "a", "Z", "0", " ", "\n", "\r\n", "\t", "\x00", "\x1f", "\x7f",
        "🇺", "🇸", "😀", "\ud83c", "é", "م", "–", "≤", "\u200b", "{", "}", ",", ":", "[", "]",
        "![]", "(", ")", "<br>", "<img src=\"data:image/png;base64,QUJD\">", "![](data:image/png;base64,QUJD)",
        "data:image/gif;base64,R0lGODlh", "base64,", "/",
    ]

    def test_random_input_always_yields_a_valid_ascii_payload(self):
        rng = random.Random(20261021)
        for _ in range(4000):
            sample = "".join(rng.choice(self.PIECES) for _ in range(rng.randint(0, 40)))
            value = [sample, sample[::-1]] if rng.random() < 0.1 else sample
            result = sanitize(value)
            try:
                text = ticket_text(result["description"])
            except json.JSONDecodeError as exc:  # pragma: no cover - failure path
                self.fail(f"{sample!r} -> {result['description']!r}: {exc}")
            self.assertEqual(text, result["description_plain"])
            self.assertTrue(result["description"].isascii(), sample)
            self.assertFalse(any(ord(c) < 32 and c not in "\n\t" for c in text), sample)
            self.assertFalse(any(ord(c) > 0xFFFF or 0xD800 <= ord(c) <= 0xDFFF for c in text), sample)
            self.assertNotIn("data:image", text.lower(), sample)


class PasteBlock(unittest.TestCase):
    """The block pasted under the editor's marker, run under def lines the way SOAR generates them."""

    BODY = custom_function_body()
    MARKER = "    ############################ Custom Code Goes Below This Line #################################\n"

    def pasted(self, def_line, prefix=""):
        namespace = {}  # no module-level imports: the block has to bring its own
        exec(def_line + "\n" + self.MARKER + prefix + self.BODY, namespace)
        return namespace[def_line.split()[1].split("(")[0]]

    def test_block_shape(self):
        self.assertTrue(self.BODY.isascii())
        self.assertNotIn("\t", self.BODY)
        self.assertIn("    import phantom.rules as phantom\n", self.BODY)
        self.assertTrue(self.BODY.rstrip().endswith("return outputs"))
        self.assertIn(self.MARKER, inspect.getsource(sanitize_description))

    def test_under_the_generated_header(self):
        fn = self.pasted("def sanitize_description(description=None, max_length=None, **kwargs):")
        for name, sample in SHAPED.items():
            with self.subTest(name):
                self.assertEqual(fn(description=sample), sanitize(sample))
        self.assertEqual(fn(description="x" * 50, max_length="10")["description_plain"], "xxxxxxx...")

    def test_max_length_not_declared(self):
        fn = self.pasted("def sanitize_description(description=None, **kwargs):")
        self.assertEqual(fn(description=INVALID_ESCAPE_SHAPED), sanitize(INVALID_ESCAPE_SHAPED))
        self.assertEqual(fn(description="x" * 50, max_length="10")["description_plain"], "xxxxxxx...")

    def test_text_input_with_another_name(self):
        fn = self.pasted("def sanitize_description(detailed_description=None, **kwargs):")
        self.assertEqual(fn(detailed_description=WORKING_SHAPED), sanitize(WORKING_SHAPED))

    def test_default_imports_left_above_the_block(self):
        fn = self.pasted(
            "def sanitize_description(description=None, **kwargs):",
            prefix="    import json\n    import phantom.rules as phantom\n\n",
        )
        self.assertEqual(fn(description=SCREENSHOT_SHAPED), sanitize(SCREENSHOT_SHAPED))
        self.assertEqual(fn(description=None), {"description": "", "description_plain": ""})

    def test_logs_one_debug_line(self):
        with mock.patch.object(sys.modules["phantom.rules"], "debug") as debug:
            sanitize(SCREENSHOT_SHAPED)
        debug.assert_called_once()
        self.assertIn("decoded 1 escape level(s), removed 1 embedded image(s)", debug.call_args[0][0])


if __name__ == "__main__":
    unittest.main()
