import base64
import io
import unittest

from PIL import Image

from app import RequestError, inspect_image, normalize_image, resolve_client_ip
from marketplace.security import (
    RateLimiter,
    hash_password,
    normalize_username,
    totp_code,
    validate_password,
    validate_totp_secret,
    validate_username,
    verify_password,
    verify_totp,
)


class SecurityTests(unittest.TestCase):
    def test_password_hash_round_trip_and_wrong_password(self):
        encoded = hash_password("LongPassword2026!")
        self.assertTrue(encoded.startswith("scrypt$"))
        self.assertTrue(verify_password("LongPassword2026!", encoded))
        self.assertFalse(verify_password("WrongPassword2026!", encoded))

    def test_username_normalization_and_validation(self):
        self.assertEqual(normalize_username("  Safe_User  "), "safe_user")
        self.assertIsNone(validate_username("safe_user"))
        self.assertIsNotNone(validate_username("두글자"))
        self.assertIsNotNone(validate_username("../admin"))

    def test_password_policy(self):
        self.assertIsNotNone(validate_password("short1"))
        self.assertIsNotNone(validate_password("onlyletterslong"))
        self.assertIsNotNone(validate_password("market_user2026", "market_user"))
        self.assertIsNone(validate_password("SafeMarket2026!", "neighbor"))

    def test_rate_limiter(self):
        limiter = RateLimiter(limit=2, window_seconds=60)
        self.assertTrue(limiter.allow("client"))
        self.assertTrue(limiter.allow("client"))
        self.assertFalse(limiter.allow("client"))
        limiter.clear("client")
        self.assertTrue(limiter.allow("client"))

    def test_forwarded_ip_is_used_only_for_trusted_proxy(self):
        self.assertEqual(
            resolve_client_ip("127.0.0.1", "203.0.113.7", "127.0.0.1"),
            "203.0.113.7",
        )
        self.assertEqual(
            resolve_client_ip("198.51.100.2", "203.0.113.7", "127.0.0.1"),
            "198.51.100.2",
        )
        self.assertEqual(
            resolve_client_ip("127.0.0.1", "not-an-ip", "127.0.0.1"),
            "127.0.0.1",
        )

    def test_image_header_and_dimensions_are_validated(self):
        valid_png = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
            "+A8AAQUBAScY42YAAAAASUVORK5CYII="
        )
        self.assertEqual(inspect_image(valid_png), (".png", 1, 1))
        with self.assertRaises(RequestError):
            inspect_image(b"\x89PNG\r\n\x1a\nnot-an-image")

        oversized_png = (
            b"\x89PNG\r\n\x1a\n"
            + b"\x00\x00\x00\rIHDR"
            + (7000).to_bytes(4, "big")
            + (1).to_bytes(4, "big")
        )
        with self.assertRaises(RequestError):
            inspect_image(oversized_png)

    def test_image_is_reencoded_without_exif_metadata(self):
        source = Image.new("RGB", (3, 2), "red")
        exif = source.getexif()
        exif[270] = "private metadata"
        exif[274] = 6
        original = io.BytesIO()
        source.save(original, format="JPEG", exif=exif)

        extension, normalized, width, height = normalize_image(original.getvalue())
        self.assertEqual(extension, ".jpg")
        self.assertEqual((width, height), (2, 3))
        with Image.open(io.BytesIO(normalized)) as result:
            self.assertEqual(len(result.getexif()), 0)

    def test_totp_uses_rfc_6238_compatible_codes(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        self.assertTrue(validate_totp_secret(secret))
        self.assertEqual(totp_code(secret, for_time=59), "287082")
        self.assertTrue(verify_totp(secret, "287082", for_time=59, window=0))
        self.assertFalse(verify_totp(secret, "000000", for_time=59, window=0))


if __name__ == "__main__":
    unittest.main()
