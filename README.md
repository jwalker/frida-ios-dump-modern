# Modern iOS IPA Dumper

A modern iOS application memory decryption tool built for **Frida 17.5.2+** with full support for **iOS 14.7.1 + Taurine jailbreak**.

**Status: ✅ Working and Tested** - Successfully dumps and decrypts iOS apps using Frida 17.5.2 on Taurine-jailbroken iOS 14.7.1 devices.

## Features

- ✅ Compatible with Frida 17.5.2+ (latest APIs)
- ✅ Works with Taurine jailbreak (iOS 14.7.1)
- ✅ Fast decryption using Frida's File API
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

1. **Attach**: Connects to the running app process via Frida
2. **Enumerate**: Lists all loaded modules (binaries) in the app
3. **Read Memory**: Reads decrypted code from memory (iOS decrypts encrypted binaries at runtime)
4. **Patch Header**: Modifies the Mach-O header to set `cryptid=0` (marks binary as decrypted)
5. **Dump**: Writes decrypted binaries to `/tmp` on device
6. **Download**: Transfers files from device via SCP via paramiko
7. **Package**: Creates a decrypted IPA file ready for analysis (throw it in Hopper or Binary Ninja!)

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

### Known Limitation: cryptid Flag

**Issue:** The dumped binaries may still show `cryptid 1` in the Mach-O header:

```bash
otool -l Payload/App.app/App | grep cryptid
# May show: cryptid 1
```

**Why this happens:**
- The tool dumps **decrypted code from memory** (which works correctly)
- However, patching the `cryptid` flag in the Mach-O header has compatibility issues with Frida's JavaScript environment
- The flag is just metadata - the actual code IS decrypted

**Impact:**
- ✅ **Code is fully decrypted** and functional
- ✅ Strings, symbols, and metadata are readable
- ⚠️ Some tools (like Hopper) may show "this file is ciphered" warning

**Workarounds:**

1. **Use included patch script (Recommended and fixes procedures in Hopper):**
   ```bash
   # Patch the cryptid flag to 0
   python patch_cryptid.py Payload/App.app/App

   # This creates App.patched, then replace the original:
   mv Payload/App.app/App.patched Payload/App.app/App

   # Verify:
   otool -l Payload/App.app/App | grep cryptid
   # Should now show: cryptid 0
   ```

2. **Use otool for disassembly:**
   ```bash
   # otool doesn't care about cryptid flag
   otool -tV Payload/App.app/App > disassembly.txt
   ```

3. **Force Hopper to disassemble:**
   - Load the binary in Hopper
   - Ignore the "ciphered" warning
   - Manually select code sections
   - Choose "Disassemble" from the menu

**Bottom line:** The binaries ARE decrypted and usable, just ignore the `cryptid` flag.

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
