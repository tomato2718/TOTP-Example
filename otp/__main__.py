from otp import TOTP

SECRET = "SecretString"

totp = TOTP()
code = totp.generate(SECRET)
is_valid = totp.verify(code, secret=SECRET)

print(code)
print(is_valid)