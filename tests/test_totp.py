from otp import TOTP

from .fake import FakeTimestamp

SECRET = "TEST"


class TestTOTP:
    def test_generate_anySecret_returnTOTPcode(self) -> None:
        totp = TOTP()
        totp._get_timestamp = FakeTimestamp(1726717220.000000)

        code = totp.generate(SECRET)

        assert code == "794695"

    def test_verify_validCode_returnTrue(self) -> None:
        totp = TOTP()
        totp._get_timestamp = FakeTimestamp(1726717220.000000)
        SECRET = "TEST"

        is_valid = totp.verify("794695", secret=SECRET)

        assert is_valid is True

    def test_verify_validCodeWithinLeeway_returnTrue(self) -> None:
        totp = TOTP()
        totp._get_timestamp = FakeTimestamp(1726717220.000000)
        SECRET = "TEST"

        valid_codes = ["091912", "794695", "027100"]

        assert (
            all(totp.verify(code, secret=SECRET, leeway=1) for code in valid_codes)
            is True
        )

    def test_verify_inValidCode_returnFalse(self) -> None:
        totp = TOTP()
        totp._get_timestamp = FakeTimestamp(1726717220.000000)
        SECRET = "TEST"

        is_valid = totp.verify("012345", secret=SECRET, leeway=0)

        assert is_valid is False
