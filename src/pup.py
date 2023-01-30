import io
import os.path
import struct
from enum import Enum
from typing import List

import attr

files = {
    3: "wlan_firmware.bin",
    5: "secure_modules.bin",
    6: "system_fs_image.img",
    8: "eap_fs_image.img",
    9: "recovery_fs_image.img",
    11: "preinst_fs_image.img",
    12: "system_ex_fs_image.img",
    34: "torus2_firmware.bin",
    257: "eula.xml",
    512: "orbis_swu.self",
    514: "orbis_swu.self",
    3337: "cp_firmware.bin",
}

devices = {
    1: "/dev/sflash0s0x32b",
    13: "/dev/sflash0s0x32b",
    32: "/dev/sflash0s0x32b",
    36: "/dev/sflash0s0x32b",
    40: "/dev/sflash0s0x32b",
    42: "/dev/sflash0s0x32b",
    44: "/dev/sflash0s0x32b",
    46: "/dev/sflash0s0x32b",
    2: "/dev/sflash0s0x33",
    14: "/dev/sflash0s0x33",
    33: "/dev/sflash0s0x33",
    37: "/dev/sflash0s0x33",
    43: "/dev/sflash0s0x33",
    3: "/dev/sflash0s0x38",
    34: "/dev/sflash0s0x38",
    48: "/dev/sflash0s0x38",
    4: "/dev/sflash0s1.cryptx2b",
    35: "/dev/sflash0s1.cryptx2b",
    38: "/dev/sflash0s1.cryptx2b",
    39: "/dev/sflash0s1.cryptx2b",
    45: "/dev/sflash0s1.cryptx2b",
    5: "/dev/sflash0s1.cryptx3b",
    10: "/dev/sflash0s1.cryptx40",
    9: "/dev/da0x0.crypt",
    11: "/dev/da0x1.crypt",
    7: "/dev/da0x2",
    8: "/dev/da0x3.crypt",
    6: "/dev/da0x4b.crypt",
    12: "/dev/da0x5b.crypt",
    3328: "/dev/sc_fw_update0",
    3336: "/dev/sc_fw_update0",
    3335: "/dev/sc_fw_update0",
    3329: "/dev/cd0",
    3330: "/dev/da0",
    16: "/dev/sbram0",
    17: "/dev/sbram0",
    18: "/dev/sbram0",
    19: "/dev/sbram0",
    20: "/dev/sbram0",
    21: "/dev/sbram0",
    22: "/dev/sbram0",
    3337: "cpfirm",
    15: "test",
    769: "/update",
    770: "/update",
    782: "test",
    783: "test",
}


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


@attr.define
class PUPHeader:  # pylint: disable=too-many-instance-attributes
    magic: int
    version: int
    mode: int
    endianness: int
    flags: int
    content_type: int
    product_type: int
    padding: int
    header_size: int
    hash_size: int
    file_size: int
    padding2: int
    entries_count: int
    flags2: int
    unk1C: int


@attr.define
class PUPEntry:  # pylint: disable=too-many-instance-attributes
    flags: int
    offset: int
    file_size: int
    memory_size: int

    @property
    def file_name(self) -> str:
        return files.get(self.flags >> 20, "Unknown")

    @property
    def compressed(self) -> bool:
        return self.flags & 0x8 != 0

    @property
    def blocked(self) -> bool:
        return self.flags & 0x800 != 0


def __str__(self):
    return f"""Magic: {hex(self.magic)}
Flags: {hex(self.flags)}
HeaderSize: {self.header_size}
HashSize: {self.hash_size}
fileSize: {self.file_size}
entryCount: {self.entries_count}
"""


PUP_HEADER_FORMAT = "<IBBBBBBHHHIIHHI"
PUP_ENTRY_FORMAT = "<QQQQ"


@attr.define
class PUP:
    """Represents PlayStation update patch file."""

    header: PUPHeader = attr.field(init=False)
    entries: List[PUPEntry] = attr.field(init=False, factory=list)

    @staticmethod
    def from_file(file_name: str):
        if not os.path.exists(file_name):
            raise PUPParsingException(
                f"{file_name} not exists", PUPErrorType.FILE_NOT_FOUND
            )
        with open(file_name, "rb") as f:
            return PUP().parse(f.read())

    def parse_header(self, header_data):
        self.header = PUPHeader(*struct.unpack(PUP_HEADER_FORMAT, header_data))
        if self.header.magic != 0x1D3D154F:
            raise PUPParsingException(
                f"Invalid Magic value: {hex(self.header.magic)}",
                PUPErrorType.INVALID_MAGIC,
            )

    def read_entries(self, stream: io.BytesIO):
        for _ in range(self.header.entries_count):
            entry_data = stream.read(struct.calcsize(PUP_ENTRY_FORMAT))
            self.entries.append(
                PUPEntry(*struct.unpack(PUP_ENTRY_FORMAT, entry_data))
            )

    def parse(self, data: bytes):
        stream = io.BytesIO(data)
        header_size = struct.calcsize(PUP_HEADER_FORMAT)
        header_data = stream.read(header_size)
        if len(header_data) < header_size:
            raise PUPParsingException(
                f"Data is too small to be a valid header {len(header_data)}",
                PUPErrorType.INVALID_HEADER_SIZE,
            )

        self.parse_header(header_data)
        if self.header.header_size > len(data) or self.header.file_size > len(
            data
        ):
            raise PUPParsingException(
                f"Invalid file size: {len(data)}",
                PUPErrorType.INVALID_FILE_SIZE,
            )

        self.read_entries(stream)

    def __str__(self):
        return str(self.header)
