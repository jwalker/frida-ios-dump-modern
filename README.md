# Modern iOS IPA Dumper

A modern iOS application memory decryption tool built for **Frida 17.5.2+** with full support for **iOS 14-16** and multiple jailbreaks.

**Status: ✅ Working and Tested** - Successfully dumps and decrypts iOS apps using Frida 17.5.2 on:
- iOS 14.7.1 + Taurine jailbreak (iPad mini 5)
- iOS 16.7.12 + palera1n jailbreak (iPhone 8)

## Features

- ✅ Compatible with Frida 17.5.2+ (uses NativePointer.readByteArray)
- ✅ Works with Taurine jailbreak (iOS 14.7.1)
- ✅ Works with palera1n jailbreak (iOS 16.7.12)
- ✅ Handles palera1n's `/cores/binpack/` jailbreak paths
- ✅ Fast decryption using memory dump + manual cryptid patching
- ✅ No deprecated API calls
- ✅ Clean, maintainable code
- ✅ Automatic IPA packaging
- ✅ Uses Python paramiko (no external tools needed)
- ✅ Detailed progress reporting

## Why This Tool?

The original `frida-ios-dump` (last updated 2020) uses deprecated Frida APIs that don't work with Frida 17.5.2. This tool is built from scratch using modern Frida APIs and is specifically tested with the Taurine-compatible Frida patches.

## Requirements

### macOS/Host Requirements
- Python 3.8+
- Frida 17.5.2+
- `paramiko` (Python SSH library - installed automatically)
- `iproxy` (for USB connection via libimobiledevice)

### iOS Device Requirements
- Jailbroken iOS device (tested on iOS 14.7.1 + Taurine)
- Patched frida-server running (see Frida patches in `will add my patch repo`) 
- SSH access enabled

## Installation

```bash
cd /Users/username/git/frida-ios-dump-modern

# Create virtual environment with uv:
uv venv
source .venv/bin/activate

# Install dependencies
uv pip install -r requirements.txt

# Make script executable
chmod +x dump.py
```

## Setup USB Connection

```bash
# Install libimobiledevice if needed
brew install libimobiledevice

# Start USB tunnel (in a separate terminal)
iproxy 2222 22
```

## Usage

### 1. List Installed Apps

```bash
python dump.py -l
```

### 2. Dump an Application

**Important:** The app must be running before dumping due to Taurine jailbreak restrictions.

```bash
# 1. Launch the app on your device manually
# 2. Run the dumper:

python dump.py com.example.app

# With custom SSH password:
python dump.py com.example.app -P your_password

# With custom output directory:
python dump.py com.example.app -o /path/to/output
```

### 3. Example: Dump Ventusky

```bash
# 1. Open Ventusky on your iOS device
# 2. Run:
python dump.py com.in-meteo.ventusky -P mypassword
```

## How It Works

### iOS 16 Compatible Approach (Hybrid Method)

1. **Attach**: Connects to the running app process via Frida
2. **Enumerate**: Lists all loaded modules (binaries) in the app
3. **Read Disk Binary**: Reads the original encrypted binary from device filesystem
   - **Critical for iOS 16**: Preserves LC_DYLD_CHAINED_FIXUPS data
   - Keeps original DATA segments with fixup chains intact
4. **Read Decrypted Segment**: Reads ONLY the encrypted TEXT segment from memory
   - iOS decrypts code at runtime
   - We read just the decrypted portion, not the whole binary
5. **Replace & Patch**:
   - Replace encrypted TEXT segment in disk binary with decrypted memory
   - Set cryptid=0 in LC_ENCRYPTION_INFO
   - All DATA segments remain untouched (preserves fixups)
6. **Dump**: Writes hybrid binary to `/tmp` on device
7. **Download**: Transfers files from device via SCP via paramiko
8. **Package**: Creates a decrypted IPA file ready for analysis

**Why this works on iOS 16:**
- iOS 16 uses chained fixups - pointers are stored as "chains" that dyld resolves at runtime
- Dumping from memory gives us resolved pointers, but tools expect fixup chains
- By reading disk binary and replacing only the encrypted TEXT, we preserve original fixups
- This is the same approach bagbak and other modern dumpers use

## Output

The tool creates:
- Individual decrypted binaries
- Complete app bundle with decrypted binaries
- Packaged IPA file ready for analysis

Example output structure:
```
/tmp/Ventusky_decrypted/
├── Payload/
│   └── Ventusky.app/
│       ├── Ventusky (decrypted main binary)
│       ├── Frameworks/
│       │   └── *.framework (decrypted frameworks)
│       └── ... (other app resources)
└── Ventusky_decrypted.ipa
```

## Taurine Jailbreak Compatibility

This tool is designed to work with the Taurine-patched Frida server that includes:

1. **No Thread Suspension on iOS 14**: Prevents kernel panics
2. **No launchd Injection**: Respects Taurine restrictions
3. **Manual App Launch Required**: Apps must be launched manually before dumping

## Troubleshooting

### "No USB device found"
```bash
# Check frida-server is running on device:
ssh -p 2222 root@localhost "ps aux | grep frida-server"

# Restart frida-server if needed:
ssh -p 2222 root@localhost "killall frida-server; frida-server &"
```

### "App not found"
```bash
# List apps to find correct bundle ID:
python dump.py -l
```

### "App not running"
```bash
# Launch the app manually on your device first
# This is required due to Taurine jailbreak restrictions
```

### SSH Authentication Failed
```bash
# Test SSH connection:
ssh -p 2222 root@localhost

# If password prompt works, use -P flag:
python dump.py com.example.app -P your_password
```

### iOS 16: "Objective-C Metadata looks mangled" in Hopper

If you're getting metadata errors on iOS 16 after patching:

**Diagnose the issue:**
```bash
# Run diagnostic on dumped binary
./diagnose_ios16.sh /tmp/AppName_decrypted/Payload/AppName.app/AppName

# Compare with working iOS 14 binary
./diagnose_ios16.sh /path/to/working/ios14/binary
```

**Key things to check:**
1. File size matches original binary on disk
2. Look for LC_DYLD_CHAINED_FIXUPS (iOS 16 specific)
3. Verify cryptid is 0 after patching

The tool now reads original file size from disk to avoid dumping runtime-expanded memory regions.

### Post-Dump: Verification

**Good news:** The tool now automatically sets `cryptid=0` during dumping, so manual patching is no longer required!

**iOS 16 Compatibility:** The tool uses a hybrid approach:
1. Reads original binary from disk (preserves chained fixups)
2. Replaces only encrypted TEXT segment with decrypted memory
3. Sets cryptid=0 automatically
4. Preserves all DATA segments with original fixup chains intact

This prevents "Is this a file manually extracted from the DYLD shared cache?" and "Objective-C Metadata looks mangled" errors on iOS 16.

**Verify the dump:**
```bash
# Check that cryptid is 0 (should be automatic now)
otool -l Payload/App.app/App | grep cryptid
# Should show: cryptid 0

# Check file has all segments
otool -l Payload/App.app/App | grep "segname __"
# Should show: __TEXT, __DATA_CONST, __DATA, __LINKEDIT

# Open in Hopper - should work without warnings!
```

**Manual patching (legacy - no longer needed):**

If for some reason the automatic cryptid patching didn't work:

```bash
# Check if patching needed
otool -l Payload/App.app/App | grep cryptid
# If shows cryptid 1, run:

python patch_cryptid.py Payload/App.app/App
mv Payload/App.app/App.patched Payload/App.app/App
```

**Expected result:**
- ✅ Hopper opens without "ciphered" or "mangled metadata" warnings
- ✅ All Objective-C classes and methods visible
- ✅ Procedure names properly resolved (not sub_XXXXX)
- ✅ Works on both iOS 14 (Taurine) and iOS 16 (palera1n)

**Technical Details - iOS 16 Chained Fixups:**
- **Problem**: iOS 16 uses LC_DYLD_CHAINED_FIXUPS for pointer authentication
- **Issue**: Dumping from memory gives resolved pointers, not fixup chains
- **Solution**: Hybrid approach
  1. Read original encrypted binary from disk (has fixup chains)
  2. Read ONLY decrypted TEXT segment from memory
  3. Replace encrypted TEXT in disk binary with decrypted memory
  4. Preserve DATA segments from disk (fixup chains intact)
  5. Set cryptid=0 automatically
- **Result**: Binary has decrypted code + original fixup chains = Hopper happy!

## API Differences from Old frida-ios-dump

This tool uses modern Frida 17.5.2 APIs:

| Old API (Deprecated) | New API (Modern) | Notes |
|---------------------|------------------|-------|
| `Module.ensureInitialized()` | Not needed | ObjC auto-initialized |
| `Module.findExportByName(null, 'name')` | `Module.findGlobalExportByName('name')` | Global exports |
| `Process.getModuleByName()` | `Process.findModuleByName()` | Returns null if not found |
| Manual POSIX file I/O | `new File(path, 'wb')` | Built-in File API |
| `Memory.writeByteArray()` | `file.write(arrayBuffer)` | Direct binary write |

## Support

If you find this tool useful or need further updates consider supporting the project Boba needs:

[☕ Buy Me a Boba](https://buymeacoffee.com/calleax)

## License

MIT License - Free for security research and educational purposes.

## Credits

- Built for use with Taurine-patched Frida (case study coming soon)
- Inspired by original frida-ios-dump by AloneMonkey
- Modern API implementation for Frida 17.5.2+

## Security Note

This tool is intended for:
- Security research
- CTF challenges
- Educational purposes
- ???
- Profit
