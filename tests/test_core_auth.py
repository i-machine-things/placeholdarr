from core.auth import (
    create_session_token,
    generate_webhook_api_key,
    hash_password,
    verify_password,
    verify_session_token,
)


def test_hash_password_roundtrip():
    hashed = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", hashed) is True


def test_hash_password_wrong_password_rejected():
    hashed = hash_password("correct horse battery staple")
    assert verify_password("wrong password", hashed) is False


def test_hash_password_random_salt():
    a = hash_password("same password")
    b = hash_password("same password")
    assert a != b
    assert verify_password("same password", a) is True
    assert verify_password("same password", b) is True


def test_verify_password_malformed_stored_hash_returns_false():
    assert verify_password("anything", "") is False
    assert verify_password("anything", "not-a-real-hash") is False
    assert verify_password("anything", "pbkdf2_sha512$notanumber$aa$bb") is False
    assert verify_password("anything", None) is False


def test_session_token_round_trip():
    token = create_session_token("secret-a", now=1000.0)
    assert verify_session_token(token, "secret-a", now=1000.0) is True


def test_session_token_wrong_secret_rejected():
    token = create_session_token("secret-a", now=1000.0)
    assert verify_session_token(token, "secret-b", now=1000.0) is False


def test_session_token_expired_rejected():
    token = create_session_token("secret-a", now=1000.0)
    just_ok = verify_session_token(token, "secret-a", ttl_seconds=100, now=1099.0)
    just_expired = verify_session_token(token, "secret-a", ttl_seconds=100, now=1101.0)
    assert just_ok is True
    assert just_expired is False


def test_session_token_tampered_signature_rejected():
    token = create_session_token("secret-a", now=1000.0)
    payload_part, sig_part = token.split(".", 1)
    tampered_char = "A" if sig_part[0] != "A" else "B"
    tampered = f"{payload_part}.{tampered_char}{sig_part[1:]}"
    assert verify_session_token(tampered, "secret-a", now=1000.0) is False


def test_session_token_malformed_input_never_raises():
    assert verify_session_token("", "secret-a") is False
    assert verify_session_token("garbage", "secret-a") is False
    assert verify_session_token("not.base64!!.stuff", "secret-a") is False
    assert verify_session_token(None, "secret-a") is False


def test_generate_webhook_api_key_shape_and_uniqueness():
    key_a = generate_webhook_api_key()
    key_b = generate_webhook_api_key()
    assert len(key_a) == 40
    assert all(c in "0123456789abcdef" for c in key_a)
    assert key_a != key_b
