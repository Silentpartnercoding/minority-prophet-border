import unittest

from border.jcs import CanonicalizationError, MAX_SAFE_INTEGER, canonicalize


class JcsTests(unittest.TestCase):
    def test_canonical_object_order_and_utf8(self):
        self.assertEqual(
            b'{"a":"\xe2\x82\xac","b":[true,null,2]}',
            canonicalize({"b": [True, None, 2], "a": "€"}),
        )

    def test_rejects_float_large_integer_lone_surrogate_and_non_string_key(self):
        for value in (
            {"value": 1.5},
            {"value": MAX_SAFE_INTEGER + 1},
            {"value": "\ud800"},
            {1: "value"},
        ):
            with self.assertRaises(CanonicalizationError):
                canonicalize(value)


if __name__ == "__main__":
    unittest.main()
