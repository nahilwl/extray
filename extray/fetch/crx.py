import struct

MAGIC = b"Cr24"


def crx_to_zip(data: bytes) -> bytes:
    """Strip the CRX3 header (magic, version, header size, protobuf header) and return the zip."""
    if len(data) < 12 or data[:4] != MAGIC:
        raise ValueError("not a CRX file (bad magic)")
    version, header_size = struct.unpack("<II", data[4:12])
    if version != 3:
        raise ValueError(f"unsupported CRX version {version} (only CRX3)")
    return data[12 + header_size :]
