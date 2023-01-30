import io
import os.path
import struct
from enum import Enum

import attr


class PUPErrorType(Enum):
    FILE_NOT_FOUND = 0
    INVALID_HEADER_SIZE = 1
    INVALID_MAGIC = 2
    UNKNOWN_ERROR = 3
    INVALID_FILE_SIZE = 4


class PUPParsingException(Exception):
    def __init__(self, message: str, error_type: PUPErrorType):
        self.message = message
        self.error_type = error_type

    def __str__(self):
        return f"{self.error_type}: {self.message}"


@attr.s
class PUPHeader:  # pylint: disable=too-many-instance-attributes
    magic: int = attr.ib()
    version: int = attr.ib()
    mode: int = attr.ib()
    endianness: int = attr.ib()
    flags: int = attr.ib()
    content_type: int = attr.ib()
    product_type: int = attr.ib()
    paddint: int = attr.ib()
    header_size: int = attr.ib()
    hash_size: int = attr.ib()
    file_size: int = attr.ib()
    paddint2: int = attr.ib()
    blobs_count: int = attr.ib()
    flags2: int = attr.ib()
    unk1C: int = attr.ib()

    def __str__(self):
        return f"""Magic: {hex(self.magic)}
Flags: {hex(self.flags)}
HeaderSize: {self.header_size}
HashSize: {self.hash_size}
fileSize: {self.file_size}
entryCount: {self.blobs_count}
"""


@attr.s
class PUP:
    """Represents PlayStation update patch file."""

    header: PUPHeader = attr.ib(init=False)

    @staticmethod
    def from_file(file_name: str):
        if not os.path.exists(file_name):
            raise PUPParsingException(
                f"{file_name} not exists", PUPErrorType.FILE_NOT_FOUND
            )
        with open(file_name, "rb") as f:
            return PUP().parse(f.read())

    def parse(self, data: bytes):
        stream = io.BytesIO(data)
        header_data = stream.read(32)
        if len(header_data) < 32:
            raise PUPParsingException(
                f"Data is too small to be a valid header {len(header_data)}",
                PUPErrorType.INVALID_HEADER_SIZE,
            )
        self.header = PUPHeader(
            *struct.unpack("<IBBBBBBHHHIIHHI", header_data)
        )
        if self.header.magic != 0x1D3D154F:
            raise PUPParsingException(
                f"Invalid Magic value: {hex(self.header.magic)}",
                PUPErrorType.INVALID_MAGIC,
            )
        if self.header.header_size > len(data) or self.header.file_size > len(
            data
        ):
            raise PUPParsingException(
                f"Invalid file size: {len(data)}",
                PUPErrorType.INVALID_FILE_SIZE,
            )

    def __str__(self):
        return str(self.header)
