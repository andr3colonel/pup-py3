import io
import os.path
import struct
import zlib
from enum import Enum
from typing import List

import attr

files = {
    0x1: "emc_ipl.slb",
    0x2: "eap_kbl.slb",
    0x3: "torus2_fw.slb",
    0x4: "sam_ipl.slb",
    0x5: "coreos.slb",
    0x6: "system_exfat.img",
    0x7: "eap_kernel.slb",
    0x8: "eap_vsh_fat16.img",
    0x9: "preinst_fat32.img",
    0xA: "",  # sflash0s1.cryptx40
    0xB: "preinst2_fat32.img",
    0xC: "system_ex_exfat.img",
    0xD: "emc_ipl.slb",
    0xE: "eap_kbl.slb",
    0xF: "",  # test
    0x10: "",  # sbram0
    0x11: "",  # sbram0
    0x12: "",  # sbram0
    0x13: "",  # sbram0
    0x14: "",  # sbram0
    0x15: "",  # sbram0
    0x16: "",  # sbram0
    # 0x17 - 0x1F
    0x20: "emc_ipl.slb",
    0x21: "eap_kbl.slb",
    0x22: "torus2_fw.slb",
    0x23: "sam_ipl.slb",
    0x24: "emc_ipl.slb",
    0x25: "eap_kbl.slb",
    0x26: "sam_ipl.slb",
    0x27: "sam_ipl.slb",
    0x28: "emc_ipl.slb",
    # 0x29
    0x2A: "emc_ipl.slb",
    0x2B: "eap_kbl.slb",
    0x2C: "emc_ipl.slb",
    0x2D: "sam_ipl.slb",
    0x2E: "emc_ipl.slb",
    # 0x2F
    0x30: "torus2_fw.bin",
    0x31: "sam_ipl.slb",
    0x32: "sam_ipl.slb",
    # 0x33 - 0x100
    0x101: "eula.xml",
    # 0x102 - 0x1FF
    0x200: "orbis_swu.elf",
    # 0x201
    0x202: "orbis_swu.self",
    # 0x203 - 0x300
    0x301: "",  # update
    0x302: "",  # update
    0x30E: "",  # test
    0x30F: "",  # test
    # 0x310 - 0xCFF
    0xD00: "",  # sc_fw_update0
    0xD01: "bd_firm.slb",
    0xD02: "sata_bridge_fw.slb",
    # 0xD03 - 0xD06
    0xD07: "",  # sc_fw_update0
    0xD08: "",  # sc_fw_update0
    0xD09: "cp_fw_kernel.slb",
    # 0xD0A - 0xF01
    0xF02: "",  # watermark
    0xF03: "",  # watermark
}

devices = {
    1: "/dev/sflash0s0x32b",
    2: "/dev/sflash0s0x33",
    3: "/dev/sflash0s0x38",
    4: "/dev/sflash0s1.cryptx2b",
    5: "/dev/sflash0s1.cryptx3b",
    6: "/dev/da0x4b.crypt",
    7: "/dev/da0x2",
    8: "/dev/da0x3.crypt",
    9: "/dev/da0x0.crypt",
    10: "/dev/sflash0s1.cryptx40",
    11: "/dev/da0x1.crypt",
    12: "/dev/da0x5b.crypt",
    13: "/dev/sflash0s0x32b",
    14: "/dev/sflash0s0x33",
    15: "test",
    16: "/dev/sbram0",
    17: "/dev/sbram0",
    18: "/dev/sbram0",
    19: "/dev/sbram0",
    20: "/dev/sbram0",
    21: "/dev/sbram0",
    22: "/dev/sbram0",
    32: "/dev/sflash0s0x32b",
    33: "/dev/sflash0s0x33",
    34: "/dev/sflash0s0x38",
    36: "/dev/sflash0s0x32b",
    37: "/dev/sflash0s0x33",
    35: "/dev/sflash0s1.cryptx2b",
    38: "/dev/sflash0s1.cryptx2b",
    39: "/dev/sflash0s1.cryptx2b",
    40: "/dev/sflash0s0x32b",
    42: "/dev/sflash0s0x32b",
    44: "/dev/sflash0s0x32b",
    46: "/dev/sflash0s0x32b",
    43: "/dev/sflash0s0x33",
    48: "/dev/sflash0s0x38",
    45: "/dev/sflash0s1.cryptx2b",
    769: "/update",
    770: "/update",
    782: "test",
    783: "test",
    3328: "/dev/sc_fw_update0",
    3329: "/dev/cd0",
    3330: "/dev/da0",
    3335: "/dev/sc_fw_update0",
    3336: "/dev/sc_fw_update0",
    3337: "cpfirm",
}


class Endianness(Enum):
    UNKNOWN = 0
    LITTLE = 1
    BIG = 2

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class PUPErrorType(Enum):
    FILE_NOT_FOUND = 0
    INVALID_HEADER_SIZE = 1
    INVALID_MAGIC = 2
    UNKNOWN_ERROR = 3
    INVALID_FILE_SIZE = 4


class PUPContentType(Enum):
    ELF = 1
    PUP = 4
    UNKNOWN = 0x10

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


class PUPProductType(Enum):
    PUP = 0
    ELF = 8
    PRX = 9
    K = 0xC
    SM = 0xE
    SL = 0xF
    UNKNOWN = 0x10

    @classmethod
    def _missing_(cls, value):
        return cls.UNKNOWN


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
    endian: int
    flags: int
    content: int
    product: int
    padding: int
    header_size: int
    hash_size: int
    file_size: int
    padding2: int
    entries_count: int
    flags2: int
    unk1C: int

    @property
    def endianness(self) -> Endianness:
        return Endianness(self.endian)

    @property
    def content_type(self) -> PUPContentType:
        return PUPContentType(self.content)

    @property
    def product_type(self) -> PUPProductType:
        return PUPProductType(self.product)

    def __str__(self):
        return f"""Version: {self.version}
Endianess: {self.endianness}
Content type: {self.content_type}
Product type: {self.product_type}
Header size: {hex(self.header_size)}
File size: {hex(self.file_size)}
Entries: {self.entries_count}
    """


@attr.define
class PUPEntry:  # pylint: disable=too-many-instance-attributes
    flags: int
    offset: int
    file_size: int
    memory_size: int
    data: bytes = attr.field(init=False)

    @property
    def file_name(self) -> str:
        return files.get(self.flags >> 20, "Unknown")

    @property
    def compressed(self) -> bool:
        return self.flags & 0x8 != 0

    @property
    def blocked(self) -> bool:
        return self.flags & 0x800 != 0

    def process_bytes(self, data):
        if self.compressed:
            decompress = zlib.decompressobj()
            inflated = decompress.decompress(data)
            inflated += decompress.flush()
            self.data = inflated
        else:
            self.data = data

    def __str__(self):
        return f"""
{self.file_name}
    Compressed: {self.compressed}
    Blocked: {self.blocked}
    Offset: {hex(self.offset)}
    File size: {hex(self.file_size)}
    Uncompressed size: {hex(self.memory_size)}
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
        for entry in self.entries:
            stream.seek(entry.offset, 0)
            entry.process_bytes(stream.read(entry.file_size))

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
        return self

    def __str__(self):
        res = str(self.header)
        for entry in self.entries:
            res += str(entry)
        return res
