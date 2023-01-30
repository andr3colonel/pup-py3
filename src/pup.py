import io
import struct
from enum import Enum

import attr


class PUPErrorType(Enum):
    INVALID_HEADER_SIZE = 1
    INVALID_MAGIC = 2
    UNKNOWN_ERROR = 3


class PUPParsingException(Exception):
    def __init__(self, message: str, error_type: PUPErrorType):
        self.message = message
        self.error_type = error_type

    def __str__(self):
        return f"{self.error_type}: {self.message}"


@attr.s
class PUPHeader:  # pylint: disable=too-many-instance-attributes
    magic: int = attr.ib()
    unk04: int = attr.ib()
    unk08: int = attr.ib()
    flags: int = attr.ib()
    unk0B: int = attr.ib()
    headerSize: int = attr.ib()
    hashSize: int = attr.ib()
    fileSize: int = attr.ib()
    entryCount: int = attr.ib()
    hashCount: int = attr.ib()
    unk1C: int = attr.ib()


@attr.s
class PUP:
    """Represents PlayStation update patch file."""

    header: PUPHeader = attr.ib(init=False)

    @staticmethod
    def from_file(file_name: str):
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
        self.header = PUPHeader(*struct.unpack("<IIHBBHHQHHI", data))
        if self.header.magic != 0x1D3D154F:
            raise PUPParsingException(
                f"Invalid Magic value: {hex(self.header.magic)}",
                PUPErrorType.INVALID_MAGIC,
            )
