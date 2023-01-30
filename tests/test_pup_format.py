import pytest

from src.pup import PUP, PUPErrorType, PUPParsingException


def test_small_file():
    with pytest.raises(PUPParsingException) as e_info:
        PUP().parse(b"\x15\x4f\x1d\x3d\x01\x00\x12"
                    b"\x01\x00\x04\x00\x00\x05\xa0")
        assert e_info.error_type == PUPErrorType.INVALID_HEADER_SIZE
