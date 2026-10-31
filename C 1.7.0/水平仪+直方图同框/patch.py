"""Patch exactly Nikon Z7 II C1.70: horizon + histogram.

Standard library only. Reproduces one fixed, previously built update package.
The fixed update digest is valid only for these exact bytes; no signing key
or general-purpose signing operation is included.
"""
import argparse
import binascii
import hashlib
from pathlib import Path
import struct


STOCK_SHA256 = "fc0e94f57500a1f0e287c6b9a036c81a5ffceccb8432a377d645b3fa35a19b6a"
STOCK_SIZE = 48494024
STOCK_MASTER_SHA256 = "478caf02dba41fa9144c0c4b6e1a051dc556d40e51a79a308bdd1169efb9dbbe"
PATCHED_SHA256 = "47061182e9b13e14f7214dd2e5b9f798b55e3264258a567e8574e6074bd2c51b"
PATCHED_MASTER_SHA256 = "576acfcbb0c3c207eaee9017e6eff34e232f657e71c2833251a07da09dc5aeaa"
PATCHED_SIZE = 48494092
# Already verified update-header digest for this exact candidate.
UPDATE_DIGEST = bytes.fromhex("b48fcae58deb4b8a9b4b26b95b2f440699af6f11")
# Public XOR encoding tables extracted from the stock master at 0x19600D0.
ENCODING_TABLES = bytes.fromhex(
    "a8be06a33deb1cf9e5138487728ddcadd4270e1b087a12f674b7ce52d0d8c27c496b28e8649550ddda99e93f100b9dde"
    "225c2a2442519a0a2e75fde0f1979ec31da51e8c9bec58a2652947fc79d754abf23376cad9f85e6eafd3faaeb5853b34"
    "cda1830f01022ca6e2462fc56a6f5b7848ef04407323d162c730f003f526a0bf70edcf81b4aab9b61196947e44327d14"
    "38803e66ba1618891588e65663c4f78b053c983a676d8a437f574b17fb7bb0095f91c6c0d5602b86ffea3992358fee90"
    "1fb121b3bb8e69254f716cbd364c0c0d20b8c82de4acdbd207e1a461bcc1e7824ee3004dcb19d677a7b2375d684acc1a"
    "55df41f393fef45ac9a953459f9c3159bdc488121017508285897c54279ed2da93e8a26973a323e05a38d1ff26c1cd42"
    "79b2e10325687e1b36dc3205bff28c0e0a964db4a1602e3e025dbad7c2ee1847c7c97a83b78df5c3b0ca9fa07284063a"
    "9a9b926f6ca7f47d56778755ddfc6a0ba52911f6e9002c90539859fd5b67faefea0da8fe7f97d4bc812fc6d8460c52b5"
    "4af7abe33b7449e7b3b194584fbb21514519ec2b04a6db579dccd931ed5c4b282aaa41be629115d59586adc57180eb8b"
    "634499b6142d64a475375f6bf1f88edfa9cb4c6578401f013422cf43078a1c1d705ef9d333b9aef0e2668fd00913d66e"
    "16ac1efb6d24e43948e6c876dee51ab89c61304e3fafc00f3c20f3083dce357ba4ae8d306809fb450d708bb17334fd7e"
    "487d16159b6177175699cd18c42d26e31f33a96ae9d044ec836cc387f5f63a22b5904e819a2131395bf22e504de1285f"
    "08de0c10d7ac20fcbdc9eaa63fc69114ef045ec88eaff989ca9ee6e5ccadee98c21e40fa64e4a7367627ba55a1d5a229"
    "37a34cdd439dfe6f927935bc1b63b019bec0595c5385da003b67c732d2a5eddf3e5a6e9584d14f4660c5f7ff05710a69"
    "f41123d4b902138cb24bb3948a6b0696781ddc2b80668293077f86aa52a8f32a4a75b7bbf8d6cb123de7f09f41496d01"
    "6225f15d7ab62fbfa051e80f3824033cce1c57ab9cb4c1d988b854588fe21a7b7247dbcf740bd37c42ebe0d82c0e6597"
)
TRAMPOLINES = bytes.fromhex(
    "10b5002490f89e01022803d0032801d0014b1847014b18477b03621055036210074c90f89e01022803d0032801d0024b1847024b184700bff39e5510eb9e551024aa9410"
)
# All offsets below are in the decoded master, not the encrypted update file.
EDITS = (
    (0x600348, bytes.fromhex("10b5002490f89e01022812d1"),
     bytes.fromhex("dff800f0797b491200bf00bf")),
    (0x539EE0, bytes.fromhex("c74c90f89e01022803d1"),
     bytes.fromhex("dff800f0997b491200bf")),
    (0x2399844, struct.pack("<9I", *([0x444] * 9)),
     struct.pack("<9I", *([0xCCC] * 9))),

)
MEMBER_NAMES = (
    b"ex1840_013000.bi", b"_tpj01_v140.bin", b"eg1840_mas_01700",
    b"vr1840_010100.bi", b"eg1840_sla_01700",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def crc(data):
    return binascii.crc_hqx(data, 0)


def transform(body):
    """Symmetric stock XOR encoding; retain the 32-byte plaintext marker."""
    low = ENCODING_TABLES[:256]
    middle = ENCODING_TABLES[256:512]
    high = ENCODING_TABLES[512:]
    output = bytearray(body)
    for start in range(0, len(body), 256):
        block = body[start:start + 256]
        size = len(block)
        mask = middle[(start >> 8) & 255] ^ high[(start >> 16) & 255]
        value = (int.from_bytes(block, "big")
                 ^ int.from_bytes(low[:size], "big")
                 ^ int.from_bytes(bytes([mask]) * size, "big"))
        output[start:start + size] = value.to_bytes(size, "big")
    output[:32] = body[:32]
    return bytes(output)


def parse(body):
    require(body[:32] == b" " * 32, "Invalid container marker")
    require(struct.unpack_from(">4I", body, 32) == (5, 0xD0, 0, 0),
            "Invalid container directory")
    members = []
    cursor = 0xD0
    for index, expected_name in enumerate(MEMBER_NAMES):
        name, start, size, reserved1, reserved2 = struct.unpack_from(
            ">16s4I", body, 48 + index * 32)
        require(name.rstrip(b"\0") == expected_name
                and reserved1 == reserved2 == 0
                and start == cursor and size >= 2
                and start + size <= len(body) - 16,
                "Unexpected member identity or bounds")
        member = body[start:start + size]
        require(crc(member) == 0, "Invalid member CRC")
        members.append(member)
        cursor += size
    require(cursor == len(body) - 16 and body[-14:] == bytes(14)
            and crc(body[:cursor + 2]) == 0, "Invalid container CRC or trailer")
    return members


def build(original):
    actual = sha256(original)
    require(len(original) == STOCK_SIZE and actual == STOCK_SHA256,
            f"Stock SHA256 mismatch: expected {STOCK_SHA256}, got {actual}")
    body = transform(original[32:])
    members = parse(body)
    require(sha256(members[2]) == STOCK_MASTER_SHA256,
            "Stock master SHA256 mismatch")
    master = bytearray(members[2][:-2])
    for offset, expected, replacement in EDITS:
        require(len(expected) == len(replacement)
                and master[offset:offset + len(expected)] == expected,
                f"Unexpected original bytes at master offset 0x{offset:X}")
        master[offset:offset + len(expected)] = replacement
    master.extend(TRAMPOLINES)
    master.extend(crc(master).to_bytes(2, "big"))
    require(sha256(master) == PATCHED_MASTER_SHA256,
            "Patched master SHA256 mismatch")

    patched_members = list(members)
    patched_members[2] = bytes(master)
    rebuilt = bytearray(body[:0xD0])
    for index, member in enumerate(patched_members):
        struct.pack_into(">2I", rebuilt, 48 + index * 32 + 16,
                         len(rebuilt), len(member))
        rebuilt.extend(member)
    rebuilt.extend(crc(rebuilt).to_bytes(2, "big") + bytes(14))
    candidate = UPDATE_DIGEST + original[20:32] + transform(rebuilt)
    actual = sha256(candidate)
    require(len(candidate) == PATCHED_SIZE and actual == PATCHED_SHA256,
            f"Patched SHA256 mismatch: expected {PATCHED_SHA256}, got {actual}")
    require(parse(transform(candidate[32:])) == patched_members,
            "Output container round-trip mismatch")
    return candidate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path, help="Unmodified Z7_2_0170.bin")
    parser.add_argument("-o", "--output", type=Path,
                        default=Path(__file__).resolve().with_name("Z7_2_0170.bin"),
                        help="New output file (default: beside this script)")
    args = parser.parse_args()
    try:
        require(args.original.resolve() != args.output.resolve(),
                "Input and output must be different files")
        require(not args.output.exists(), "Output already exists; refusing to overwrite")
        candidate = build(args.original.read_bytes())
        # Exclusive creation also prevents overwriting a file created during build.
        with args.output.open("xb") as stream:
            try:
                require(stream.write(candidate) == len(candidate), "Incomplete output write")
                stream.flush()
                require(sha256(args.output.read_bytes()) == PATCHED_SHA256,
                        "Output read-back SHA256 mismatch")
            except BaseException:
                stream.close()
                args.output.unlink()
                raise
    except (OSError, ValueError, struct.error) as error:
        parser.exit(1, f"Error: {error}\n")
    print(f"Stock SHA256:   {STOCK_SHA256}")
    print(f"Patched SHA256: {PATCHED_SHA256}")
    print(f"Written: {args.output.resolve()}")


if __name__ == "__main__":
    main()
