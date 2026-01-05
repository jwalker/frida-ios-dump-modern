#!/usr/bin/env python3
"""
Patch the cryptid flag in a Mach-O binary to mark it as decrypted.

Usage:
    python3 patch_cryptid.py /path/to/binary

This is a workaround for the frida-ios-dump-modern tool which successfully
decrypts binaries from memory but has issues patching the cryptid flag in
Frida's JavaScript environment. It sorta of work and is optional.

"""

import sys
import struct
from pathlib import Path


def patch_cryptid(binary_path):
    """Patch the cryptid field in LC_ENCRYPTION_INFO to 0."""

    print(f"[*] Patching: {binary_path}")

    # Read the binary
    with open(binary_path, 'rb') as f:
        data = bytearray(f.read())

    # Check magic
    magic = struct.unpack('<I', data[0:4])[0]

    if magic == 0xfeedfacf:  # MH_MAGIC_64
        is_64bit = True
        print("[*] Mach-O: 64-bit")
    elif magic == 0xfeedface:  # MH_MAGIC
        is_64bit = False
        print("[*] Mach-O: 32-bit")
    else:
        print(f"[!] Not a valid Mach-O file (magic: 0x{magic:08x})")
        return False

    # Parse header
    ncmds = struct.unpack('<I', data[16:20])[0]

    # Start of load commands
    offset = 32 if is_64bit else 28

    print(f"[*] Load commands: {ncmds}")

    # Find LC_ENCRYPTION_INFO
    found = False
    for i in range(ncmds):
        cmd = struct.unpack('<I', data[offset:offset+4])[0]
        cmdsize = struct.unpack('<I', data[offset+4:offset+8])[0]

        # LC_ENCRYPTION_INFO = 0x21, LC_ENCRYPTION_INFO_64 = 0x2C
        if cmd == 0x21 or cmd == 0x2C:
            cmd_name = "LC_ENCRYPTION_INFO_64" if cmd == 0x2C else "LC_ENCRYPTION_INFO"

            cryptoff = struct.unpack('<I', data[offset+8:offset+12])[0]
            cryptsize = struct.unpack('<I', data[offset+12:offset+16])[0]
            cryptid = struct.unpack('<I', data[offset+16:offset+20])[0]

            print(f"[*] Found {cmd_name}")
            print(f"[*]   cryptoff: {cryptoff}")
            print(f"[*]   cryptsize: {cryptsize}")
            print(f"[*]   cryptid: {cryptid} (before patch)")

            if cryptid == 0:
                print("[*] Already decrypted (cryptid = 0)")
                return True

            # Patch cryptid to 0
            struct.pack_into('<I', data, offset+16, 0)

            # Verify
            new_cryptid = struct.unpack('<I', data[offset+16:offset+20])[0]
            print(f"[+] Patched cryptid: {new_cryptid}")

            found = True
            break

        offset += cmdsize

    if not found:
        print("[!] LC_ENCRYPTION_INFO not found")
        return False

    # Write patched binary
    output_path = str(binary_path) + ".patched"
    with open(output_path, 'wb') as f:
        f.write(data)

    print(f"[+] Patched binary saved to: {output_path}")
    print(f"[*] Replace original with: mv {output_path} {binary_path}")

    return True


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 patch_cryptid.py <binary_path>")
        print("")
        print("Example:")
        print("  python3 patch_cryptid.py Payload/Pandora.app/Pandora")
        print("")
        print("This will create Payload/Pandora.app/Pandora.patched")
        sys.exit(1)

    binary_path = Path(sys.argv[1])

    if not binary_path.exists():
        print(f"[!] File not found: {binary_path}")
        sys.exit(1)

    if not binary_path.is_file():
        print(f"[!] Not a file: {binary_path}")
        sys.exit(1)

    print("━" * 60)
    print("Mach-O cryptid Patcher")
    print("━" * 60)

    success = patch_cryptid(binary_path)

    print("━" * 60)

    if success:
        print("[✓] Patch complete!")
        sys.exit(0)
    else:
        print("[✗] Patch failed!")
        sys.exit(1)


if __name__ == '__main__':
    main()
