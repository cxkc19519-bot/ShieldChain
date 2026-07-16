import pytest

from saga.domain.encoding import (
    EncodingError,
    EndpointValue,
    b64url_decode,
    b64url_encode,
    require_unix_ms,
)


def test_unpadded_base64url_round_trip() -> None:
    assert b64url_encode(b"\xfb\xff\x00") == "-_8A"
    assert b64url_decode("-_8A") == b"\xfb\xff\x00"
    assert b64url_encode(b"") == ""
    assert b64url_decode("") == b""


@pytest.mark.parametrize("value", ["-_8A=", "-_8A\n", "+/8A", "-_8*", "A"])
def test_base64url_rejects_noncanonical_values(value: str) -> None:
    with pytest.raises(EncodingError, match="invalid Base64URL"):
        b64url_decode(value)


@pytest.mark.parametrize("value", [-1, True, False, 1.0, "1", None])
def test_unix_milliseconds_are_nonnegative_plain_integers(value: object) -> None:
    with pytest.raises(EncodingError, match="invalid Unix milliseconds"):
        require_unix_ms(value, "issued_at")


def test_endpoint_is_immutable_and_validated() -> None:
    endpoint = EndpointValue(device="worker-1", ip="192.0.2.10", port=8443)
    assert endpoint.as_canonical_value() == {
        "device": "worker-1",
        "ip": "192.0.2.10",
        "port": 8443,
    }


@pytest.mark.parametrize("ip", ["example.com", "192.168.001.1", "2001:0db8::1"])
def test_endpoint_accepts_only_canonical_ip_literals(ip: str) -> None:
    with pytest.raises(EncodingError, match="invalid endpoint"):
        EndpointValue(device="worker-1", ip=ip, port=8443)


@pytest.mark.parametrize("control", ["\x00", "\x7f", "\u0085"])
def test_endpoint_device_rejects_all_unicode_cc(control: str) -> None:
    with pytest.raises(EncodingError, match="invalid endpoint"):
        EndpointValue(device=f"worker{control}", ip="192.0.2.10", port=8443)
