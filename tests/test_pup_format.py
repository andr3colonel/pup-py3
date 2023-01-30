import struct

import pytest

from src.pup import (
    PUP,
    Endianness,
    PUPContentType,
    PUPErrorType,
    PUPParsingException,
    PUPProductType,
)

pup_header_encoded_invalid_type = (
    0x1D3D154F,  # magic
    0,  # version
    0x1,  # mode
    0x5,  # endianness
    0x12,  # flags
    0x50,  # content type
    0x50,  # product type
    0x0,  # padding
    0x100,  # header size,
    0x0,  # hash size
    0x100,  # file size
    0x0,  # padding
    0x1,  # number of entries
    0x0,  # flags2
    0x0,  # padding
)


pup_header_encoded_invalid_magic = (
    0xDEADBEEF,  # magic
    0,  # version
    0x1,  # mode
    0x5,  # endianness
    0x12,  # flags
    0x50,  # content type
    0x50,  # product type
    0x0,  # padding
    0x100,  # header size,
    0x0,  # hash size
    0x100,  # file size
    0x0,  # padding
    0x1,  # number of entries
    0x0,  # flags2
    0x0,  # padding
)

pup_header_encoded = (
    0x1D3D154F,  # magic
    0,  # version
    0x1,  # mode
    0x2,  # endianness
    0x12,  # flags
    0x4,  # content type
    0x9,  # product type
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
pup_header_invalid_magic = struct.pack(
    "<IBBBBBBHHHIIHHI", *pup_header_encoded_invalid_magic
)
pup_header_invalid_type = struct.pack(
    "<IBBBBBBHHHIIHHI", *pup_header_encoded_invalid_type
)
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
        PUP().parse(pup_header_invalid_magic)
        assert e_info.error_type == PUPErrorType.INVALID_MAGIC


def test_magic_valid():
    pup = PUP()
    pup.parse_header(pup_header)
    assert pup.header.magic == 0x1D3D154F


def test_header_size_invalid():
    with pytest.raises(PUPParsingException) as e_info:
        PUP().parse(pup_header)
        assert e_info.error_type == PUPErrorType.INVALID_FILE_SIZE


def test_header_size_valid():
    pup = PUP()
    pup.parse_header(pup_header)
    assert pup.header.header_size == 0x100
    assert pup.header.file_size == 0x100


def test_header_flags():
    pup = PUP()
    pup.parse_header(pup_header)
    assert pup.header.product_type == PUPProductType.PRX
    assert pup.header.content_type == PUPContentType.PUP
    assert pup.header.endianness == Endianness.BIG


def test_header_flags_unknown():
    pup = PUP()
    pup.parse_header(pup_header_invalid_type)
    assert pup.header.product_type == PUPProductType.UNKNOWN
    assert pup.header.content_type == PUPContentType.UNKNOWN
    assert pup.header.endianness == Endianness.UNKNOWN


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
