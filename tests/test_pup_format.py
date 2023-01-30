import struct

import pytest

from src.pup import PUP, PUPErrorType, PUPParsingException

pup_header_encoded = (
    0x1D3D154F,  # magic
    0,  # version
    0x1,  # mode
    0x1,  # endianness
    0x12,  # flags
    0x4,  # content type
    0x0,  # product type
    0x0,  # padding
    0x100,  # header size,
    0x0,  # hash size
    0x100,  # file size
    0x0,  # padding
    0x1,  # number of entries
    0x0,  # flags2
    0x0,  # padding
)

pup_header = struct.pack("<IBBBBBBHHHIIHHI", *pup_header_encoded)
pup_entries = struct.pack(
    "<QQQQ", 0x10106C0E, 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC
)
pup_content = b"\x00" * 0xC0

pup_data = pup_header + pup_entries + pup_content


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
    pup.parse(pup_data)
    assert pup.header.magic == 0x1D3D154F


def test_header_size_invalid():
    with pytest.raises(PUPParsingException) as e_info:
        PUP().parse(pup_header)
        assert e_info.error_type == PUPErrorType.INVALID_FILE_SIZE


def test_header_size_valid():
    pup = PUP()
    pup.parse(pup_data)
    assert pup.header.header_size == 0x100
    assert pup.header.file_size == 0x100


def test_number_of_entries():
    pup = PUP()
    pup.parse(pup_data)
    assert len(pup.entries) == 1
    assert pup.entries[0].compressed is True
    assert pup.entries[0].blocked is True
    assert pup.entries[0].file_name == "eula.xml"
    assert pup.entries[0].offset == 0xAAAAAAAA
    assert pup.entries[0].file_size == 0xBBBBBBBB
    assert pup.entries[0].memory_size == 0xCCCCCCCC
