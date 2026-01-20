#!/bin/bash
# Diagnostic script to identify iOS 16 binary differences

if [ $# -eq 0 ]; then
    echo "Usage: $0 <path-to-dumped-binary>"
    echo "Example: $0 /tmp/DysonLink_decrypted/DysonLink"
    exit 1
fi

BINARY="$1"

if [ ! -f "$BINARY" ]; then
    echo "[!] File not found: $BINARY"
    exit 1
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "iOS 16 Binary Diagnostics"
echo "Binary: $BINARY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo ""
echo "1. Mach-O Header:"
otool -h "$BINARY"

echo ""
echo "2. Encryption Info:"
otool -l "$BINARY" | grep -A 4 LC_ENCRYPTION

echo ""
echo "3. Chained Fixups (iOS 16 specific):"
otool -l "$BINARY" | grep -A 10 "LC_DYLD_CHAINED_FIXUPS\|LC_DYLD_EXPORTS_TRIE"

echo ""
echo "4. File Size vs Segments:"
echo "   File size: $(stat -f %z "$BINARY") bytes"
echo "   Segment sizes:"
otool -l "$BINARY" | grep -A 8 "segname __TEXT\|segname __DATA"

echo ""
echo "5. ObjC Metadata Sections:"
otool -l "$BINARY" | grep -A 2 "__objc_classlist\|__objc_protolist\|__objc_imageinfo"

echo ""
echo "6. First 64 bytes (hex):"
xxd -l 64 "$BINARY"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
