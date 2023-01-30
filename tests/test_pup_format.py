import pytest

from src.pup import PUP, PUPErrorType, PUPParsingException


def test_file_not_exists():
    with pytest.raises(PUPParsingException) as e_info:
        PUP.from_file("/NONEXISTANTFILE")
        assert e_info.error_type == PUPErrorType.FILE_NOT_FOUND


def test_empty_file():
    with pytest.raises(PUPParsingException) as e_info:
        PUP().parse(b"")
        assert e_info.error_type == PUPErrorType.INVALID_HEADER_SIZE


def test_magic_invalid():
    with pytest.raises(PUPParsingException) as e_info:
        PUP().parse(
            b"\x15\x4f\x1d\x3d\x01\x00\x12\x00"
            b"\x01\x00\x04\x00\x00\x05\xa0\x00"
            b"\x01\x01\x01\x01\x01\x01\x01\x00"
            b"\x01\x01\x01\x01\x01\x01\x01\x00"
        )
        assert e_info.error_type == PUPErrorType.INVALID_MAGIC


def test_magic_valid():
    pup = PUP()
    pup.parse(
        b"\x4f\x15\x3d\x1d\x00\x01\x01\x12"
        b"\x04\x00\x00\x00\xa0\x05\xc0\x09"
        b"\xca\xe2\x2e\x0d\x00\x00\x00\x00"
        b"\x1c\x00\x22\x00\x00\x00\x00\x00"
    )
    assert pup.header.magic == 0x1D3D154F
