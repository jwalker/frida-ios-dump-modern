/**
 * Modern iOS IPA Dumper Agent for Frida 17.5.2+
 * Compatible with iOS 14.7.1 + Taurine patches
 *
 * Uses Frida's built-in File API with POSIX fallback for compatibility
 */

// Check if File API is available, otherwise use POSIX fallback
const FILE_API_AVAILABLE = (typeof File !== 'undefined');

// POSIX fallback functions (only if File API unavailable)
let openFunc = null, writeFunc = null, closeFunc = null;

if (!FILE_API_AVAILABLE) {
    console.log('[!] File API not available, using POSIX fallback');
    const openPtr = Module.findGlobalExportByName('open');
    const writePtr = Module.findGlobalExportByName('write');
    const closePtr = Module.findGlobalExportByName('close');

    if (openPtr && writePtr && closePtr) {
        openFunc = new NativeFunction(openPtr, 'int', ['pointer', 'int', 'int']);
        writeFunc = new NativeFunction(writePtr, 'int', ['int', 'pointer', 'int']);
        closeFunc = new NativeFunction(closePtr, 'int', ['int']);
    } else {
        console.log('[!] Failed to initialize POSIX functions');
    }
}

const O_WRONLY = 1;
const O_CREAT = 0x0200;
const O_TRUNC = 0x0400;

/**
 * Write data using POSIX functions (fallback when File API unavailable)
 */
function writePOSIX(path, data) {
    if (!openFunc || !writeFunc || !closeFunc) {
        console.log(`[!] POSIX functions not available`);
        return false;
    }

    try {
        const pathPtr = Memory.allocUtf8String(path);
        const fd = openFunc(pathPtr, O_WRONLY | O_CREAT | O_TRUNC, 420); // 0644 in decimal

        if (fd === -1) {
            console.log(`[!] Failed to open ${path}`);
            return false;
        }

        // Convert ArrayBuffer to pointer
        const buffer = Memory.alloc(data.byteLength);
        const bytes = new Uint8Array(data);

        // Write in chunks to avoid memory issues
        const CHUNK_SIZE = 1024 * 1024; // 1MB chunks
        let offset = 0;

        while (offset < bytes.length) {
            const chunkSize = Math.min(CHUNK_SIZE, bytes.length - offset);
            const chunkBuffer = Memory.alloc(chunkSize);

            // Copy chunk to memory
            for (let i = 0; i < chunkSize; i++) {
                Memory.writeU8(chunkBuffer.add(i), bytes[offset + i]);
            }

            const written = writeFunc(fd, chunkBuffer, chunkSize);
            if (written === -1) {
                console.log(`[!] Write failed at offset ${offset}`);
                closeFunc(fd);
                return false;
            }

            offset += chunkSize;
        }

        closeFunc(fd);
        return true;

    } catch (e) {
        console.log(`[!] POSIX write error: ${e.message}`);
        return false;
    }
}

/**
 * Patch the LC_ENCRYPTION_INFO cryptid to mark binary as decrypted
 * Takes a Uint8Array and modifies it in place
 */
function patchCryptid(bytes) {
    try {
        // bytes is already a Uint8Array, modify it directly

        // Helper to read uint32 in little-endian
        function readUint32(offset) {
            return bytes[offset] |
                   (bytes[offset + 1] << 8) |
                   (bytes[offset + 2] << 16) |
                   (bytes[offset + 3] << 24);
        }

        // Helper to write uint32 in little-endian
        function writeUint32(offset, value) {
            bytes[offset] = value & 0xFF;
            bytes[offset + 1] = (value >>> 8) & 0xFF;
            bytes[offset + 2] = (value >>> 16) & 0xFF;
            bytes[offset + 3] = (value >>> 24) & 0xFF;
        }

        // Check Mach-O magic
        const magic = readUint32(0);
        const is64bit = (magic === 0xfeedfacf); // MH_MAGIC_64
        const is32bit = (magic === 0xfeedface); // MH_MAGIC

        if (!is64bit && !is32bit) {
            console.log('[!] Not a valid Mach-O file');
            return false;
        }

        // Parse Mach-O header
        const ncmds = readUint32(16); // Number of load commands

        // Start of load commands
        let offset = is64bit ? 32 : 28;

        console.log(`[*] Mach-O: ${is64bit ? '64-bit' : '32-bit'}, ${ncmds} load commands`);

        // Iterate through load commands to find LC_ENCRYPTION_INFO
        for (let i = 0; i < ncmds; i++) {
            const cmd = readUint32(offset);
            const cmdsize = readUint32(offset + 4);

            // LC_ENCRYPTION_INFO = 0x21, LC_ENCRYPTION_INFO_64 = 0x2C
            if (cmd === 0x21 || cmd === 0x2C) {
                const cryptoff = readUint32(offset + 8);
                const cryptsize = readUint32(offset + 12);
                const cryptid = readUint32(offset + 16);

                console.log(`[*] Found LC_ENCRYPTION_INFO${cmd === 0x2C ? '_64' : ''}`);
                console.log(`[*]   cryptoff: ${cryptoff}`);
                console.log(`[*]   cryptsize: ${cryptsize}`);
                console.log(`[*]   cryptid: ${cryptid} (before patch)`);

                if (cryptid !== 0) {
                    // Patch cryptid to 0 (decrypted)
                    writeUint32(offset + 16, 0);
                    console.log(`[+] Patched cryptid: 0 (decrypted)`);
                    return true;
                } else {
                    console.log(`[*] Already decrypted (cryptid = 0)`);
                    return true;
                }
            }

            offset += cmdsize;
        }

        console.log('[!] LC_ENCRYPTION_INFO not found');
        return false;

    } catch (e) {
        console.log(`[!] Error patching cryptid: ${e.message}`);
        return false;
    }
}

/**
 * Calculate complete file size from all Mach-O segments
 * Finds the maximum (fileoff + filesize) across all segments
 * This gives us the true end-of-file position
 */
function calculateCompleteFileSize(baseAddress) {
    try {
        // Read Mach-O header
        const magic = baseAddress.readU32();
        const is64bit = (magic === 0xfeedfacf); // MH_MAGIC_64
        const is32bit = (magic === 0xfeedface); // MH_MAGIC

        if (!is64bit && !is32bit) {
            console.log(`[!] Invalid Mach-O magic: 0x${magic.toString(16)}`);
            return null;
        }

        const ncmds = baseAddress.add(16).readU32();
        let offset = is64bit ? 32 : 28;

        // LC_SEGMENT = 0x1, LC_SEGMENT_64 = 0x19
        const LC_SEGMENT = 0x1;
        const LC_SEGMENT_64 = 0x19;

        let maxFileEnd = 0;

        console.log(`[*] Analyzing ${ncmds} load commands...`);

        // Iterate through all load commands
        for (let i = 0; i < ncmds; i++) {
            const cmd = baseAddress.add(offset).readU32();
            const cmdsize = baseAddress.add(offset + 4).readU32();

            if (cmd === LC_SEGMENT || cmd === LC_SEGMENT_64) {
                let fileoff, filesize;
                let segname;

                if (cmd === LC_SEGMENT_64) {
                    // Read segment name (16 bytes at offset 8)
                    segname = baseAddress.add(offset + 8).readCString();
                    // LC_SEGMENT_64: fileoff at offset 32, filesize at offset 40
                    fileoff = baseAddress.add(offset + 32).readU64().toNumber();
                    filesize = baseAddress.add(offset + 40).readU64().toNumber();
                } else {
                    // Read segment name
                    segname = baseAddress.add(offset + 8).readCString();
                    // LC_SEGMENT: fileoff at offset 28, filesize at offset 32
                    fileoff = baseAddress.add(offset + 28).readU32();
                    filesize = baseAddress.add(offset + 32).readU32();
                }

                // Only count segments that have file data
                if (filesize > 0 && fileoff > 0) {
                    const endOffset = fileoff + filesize;
                    if (endOffset > maxFileEnd) {
                        console.log(`[*]   Segment ${segname}: fileoff=${fileoff}, filesize=${filesize}, end=${endOffset}`);
                        maxFileEnd = endOffset;
                    }
                } else if (fileoff === 0 && filesize > 0) {
                    // __TEXT segment starts at 0
                    const endOffset = filesize;
                    if (endOffset > maxFileEnd) {
                        console.log(`[*]   Segment ${segname}: fileoff=${fileoff}, filesize=${filesize}, end=${endOffset}`);
                        maxFileEnd = endOffset;
                    }
                }
            }

            offset += cmdsize;
        }

        if (maxFileEnd === 0) {
            console.log(`[!] Could not determine file size from segments`);
            return null;
        }

        console.log(`[+] Complete file size: ${maxFileEnd} bytes (based on segment analysis)`);
        return maxFileEnd;

    } catch (e) {
        console.log(`[!] Error calculating file size: ${e.message}`);
        return null;
    }
}

/**
 * Read entire file from disk using File API or POSIX
 */
function readFileFromDisk(filePath) {
    // Try File API first
    if (FILE_API_AVAILABLE) {
        try {
            const file = new File(filePath, 'rb');
            file.seek(0, 2); // SEEK_END
            const size = file.tell();
            file.seek(0, 0); // SEEK_SET

            console.log(`[*] Reading ${size} bytes from disk...`);
            const buffer = file.readBytes(size);
            file.close();

            if (buffer && buffer.byteLength === size) {
                console.log(`[+] Read complete: ${buffer.byteLength} bytes`);
                return buffer;
            }
        } catch (e) {
            console.log(`[!] File API read failed: ${e.message}`);
        }
    }

    // POSIX fallback
    if (!openFunc || !closeFunc) {
        console.log(`[!] No POSIX functions available`);
        return null;
    }

    try {
        const lseekPtr = Module.findGlobalExportByName('lseek');
        const readPtr = Module.findGlobalExportByName('read');

        if (!lseekPtr || !readPtr) {
            console.log(`[!] Missing lseek or read function`);
            return null;
        }

        const lseekFunc = new NativeFunction(lseekPtr, 'int64', ['int', 'int64', 'int']);
        const readFunc = new NativeFunction(readPtr, 'int', ['int', 'pointer', 'uint']);

        const pathPtr = Memory.allocUtf8String(filePath);
        const fd = openFunc(pathPtr, 0, 0); // O_RDONLY

        if (fd === -1) {
            console.log(`[!] Failed to open ${filePath}`);
            return null;
        }

        // Get file size
        const size = lseekFunc(fd, 0, 2); // SEEK_END
        lseekFunc(fd, 0, 0); // SEEK_SET

        if (size <= 0) {
            console.log(`[!] Invalid file size: ${size}`);
            closeFunc(fd);
            return null;
        }

        console.log(`[*] Reading ${size} bytes from disk (POSIX)...`);

        // Allocate buffer and read
        const buffer = Memory.alloc(size);
        const bytesRead = readFunc(fd, buffer, size);
        closeFunc(fd);

        if (bytesRead !== size) {
            console.log(`[!] Read ${bytesRead} bytes, expected ${size}`);
            return null;
        }

        const arrayBuffer = buffer.readByteArray(size);
        console.log(`[+] Read complete: ${arrayBuffer.byteLength} bytes`);
        return arrayBuffer;

    } catch (e) {
        console.log(`[!] POSIX read error: ${e.message}`);
        return null;
    }
}

/**
 * Find LC_ENCRYPTION_INFO in Mach-O header
 * Returns {cryptoff, cryptsize, cryptidOffset} or null
 */
function findEncryptionInfo(bytes) {
    try {
        const magic = (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0;
        const is64bit = (magic === 0xfeedfacf >>> 0);

        if (!is64bit && magic !== (0xfeedface >>> 0)) {
            return null;
        }

        const ncmds = bytes[16] | (bytes[17] << 8) | (bytes[18] << 16) | (bytes[19] << 24);
        let offset = is64bit ? 32 : 28;

        for (let i = 0; i < ncmds; i++) {
            const cmd = bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);
            const cmdsize = bytes[offset + 4] | (bytes[offset + 5] << 8) | (bytes[offset + 6] << 16) | (bytes[offset + 7] << 24);

            // LC_ENCRYPTION_INFO = 0x21, LC_ENCRYPTION_INFO_64 = 0x2C
            if (cmd === 0x21 || cmd === 0x2C) {
                const cryptoff = bytes[offset + 8] | (bytes[offset + 9] << 8) | (bytes[offset + 10] << 16) | (bytes[offset + 11] << 24);
                const cryptsize = bytes[offset + 12] | (bytes[offset + 13] << 8) | (bytes[offset + 14] << 16) | (bytes[offset + 15] << 24);

                return {
                    cryptoff: cryptoff,
                    cryptsize: cryptsize,
                    cryptidOffset: offset + 16
                };
            }

            offset += cmdsize;
        }

        return null;
    } catch (e) {
        console.log(`[!] Error parsing Mach-O: ${e.message}`);
        return null;
    }
}

/**
 * Dump a loaded module - iOS 16 compatible approach
 * Reads original file from disk and replaces only encrypted segment
 */
function dumpModule(modulePath) {
    console.log(`[*] Dumping: ${modulePath}`);

    try {
        // Find the module in memory
        const moduleName = modulePath.split('/').pop();
        const module = Process.findModuleByName(moduleName);

        if (!module) {
            console.log(`[!] Module not found: ${moduleName}`);
            return null;
        }

        console.log(`[*] Memory base: ${module.base}, size: ${module.size}`);

        // Read original encrypted binary from disk
        // This preserves iOS 16 chained fixups in DATA segments
        console.log(`[*] Reading original binary from disk...`);
        const diskData = readFileFromDisk(modulePath);

        if (!diskData) {
            console.log(`[!] Failed to read ${modulePath} from disk`);
            console.log(`[*] Falling back to pure memory dump...`);

            // Fallback: pure memory dump
            const dumpSize = calculateCompleteFileSize(module.base) || module.size;
            const memoryData = module.base.readByteArray(dumpSize);

            if (!memoryData) {
                return null;
            }

            const outputPath = `/tmp/${moduleName}.decrypted`;
            if (FILE_API_AVAILABLE) {
                const file = new File(outputPath, 'wb');
                file.write(memoryData);
                file.close();
            } else if (!writePOSIX(outputPath, memoryData)) {
                return null;
            }

            console.log(`[+] Dumped to: ${outputPath} (memory only)`);
            return outputPath;
        }

        // Parse encryption info
        const bytes = new Uint8Array(diskData);
        const encInfo = findEncryptionInfo(bytes);

        if (!encInfo) {
            console.log(`[!] No encryption info found in binary`);
            return null;
        }

        console.log(`[*] Encryption info: cryptoff=${encInfo.cryptoff}, cryptsize=${encInfo.cryptsize}`);

        // Read decrypted segment from memory
        console.log(`[*] Reading decrypted segment from memory...`);
        const decryptedSegment = module.base.add(encInfo.cryptoff).readByteArray(encInfo.cryptsize);

        if (!decryptedSegment) {
            console.log(`[!] Failed to read decrypted segment from memory`);
            return null;
        }

        // Replace encrypted portion with decrypted data
        console.log(`[*] Replacing encrypted segment with decrypted data...`);
        const decryptedBytes = new Uint8Array(decryptedSegment);
        for (let i = 0; i < encInfo.cryptsize; i++) {
            bytes[encInfo.cryptoff + i] = decryptedBytes[i];
        }

        // Set cryptid to 0
        bytes[encInfo.cryptidOffset] = 0;
        bytes[encInfo.cryptidOffset + 1] = 0;
        bytes[encInfo.cryptidOffset + 2] = 0;
        bytes[encInfo.cryptidOffset + 3] = 0;
        console.log(`[+] Set cryptid to 0`);

        // Write result
        const outputPath = `/tmp/${moduleName}.decrypted`;
        console.log(`[*] Writing to ${outputPath}...`);

        if (FILE_API_AVAILABLE) {
            try {
                const file = new File(outputPath, 'wb');
                file.write(bytes.buffer);
                file.close();
            } catch (e) {
                console.log(`[!] File API write failed: ${e.message}`);
                if (!writePOSIX(outputPath, bytes.buffer)) {
                    return null;
                }
            }
        } else {
            if (!writePOSIX(outputPath, bytes.buffer)) {
                return null;
            }
        }

        console.log(`[+] Dumped to: ${outputPath}`);
        console.log(`[*] Method: Disk read + segment replacement (iOS 16 compatible)`);
        return outputPath;

    } catch (e) {
        console.log(`[!] Error dumping ${modulePath}: ${e.message}`);
        return null;
    }
}

/**
 * Get all loaded modules in the application
 */
function getAppModules() {
    let bundlePath = null;
    let executablePath = null;

    // Try to get bundle path from ObjC if available
    if (typeof ObjC !== 'undefined' && ObjC.available) {
        try {
            const mainBundle = ObjC.classes.NSBundle.mainBundle();
            bundlePath = mainBundle.bundlePath().toString();
            executablePath = mainBundle.executablePath().toString();
            console.log(`[*] Bundle path: ${bundlePath}`);
            console.log(`[*] Executable: ${executablePath}`);
        } catch (e) {
            console.log(`[!] Failed to get bundle via ObjC: ${e.message}`);
        }
    }

    // Fallback: enumerate all modules and find the main executable
    const processModules = Process.enumerateModules();

    if (!bundlePath && processModules.length > 0) {
        // Filter out jailbreak-related paths to find the actual app
        const jailbreakPaths = [
            '/cores/binpack/',     // palera1n
            '/usr/lib/',           // System libraries
            '/System/',            // System frameworks
            '/Library/MobileSubstrate/',  // Substrate tweaks
            '/Library/Frameworks/', // System frameworks
            '/electra/',           // Electra jailbreak
            '/chimera/',           // Chimera jailbreak
            '/odyssey/',           // Odyssey jailbreak
            '/taurine/'            // Taurine jailbreak (though this worked before)
        ];

        // Find the main app module (should be in /var/containers/Bundle/Application/ or /Applications/)
        let mainModule = null;
        for (const mod of processModules) {
            const isJailbreakModule = jailbreakPaths.some(path => mod.path.startsWith(path));
            if (!isJailbreakModule) {
                mainModule = mod;
                console.log(`[*] Found main module: ${mod.name} at ${mod.path}`);
                break;
            }
        }

        if (mainModule) {
            bundlePath = mainModule.path.substring(0, mainModule.path.lastIndexOf('/'));
            executablePath = mainModule.path;
            console.log(`[*] Detected bundle path: ${bundlePath}`);
        } else {
            console.log(`[!] Could not find main app module - all modules appear to be jailbreak-related`);
            // Last resort: use first module anyway
            const firstModule = processModules[0];
            bundlePath = firstModule.path.substring(0, firstModule.path.lastIndexOf('/'));
            console.log(`[*] Using first module as fallback: ${bundlePath}`);
        }
    }

    const modules = [];

    // Filter modules that belong to the app
    for (const mod of processModules) {
        if (bundlePath && mod.path.startsWith(bundlePath)) {
            modules.push({
                name: mod.name,
                path: mod.path,
                base: mod.base.toString(),
                size: mod.size
            });
        }
    }

    console.log(`[*] Found ${modules.length} app modules`);
    return {
        bundlePath: bundlePath,
        modules: modules
    };
}

/**
 * Main dump handler
 */
rpc.exports = {
    /**
     * List all app modules
     */
    listModules: function() {
        return getAppModules();
    },

    /**
     * Dump a specific module
     */
    dumpModule: function(modulePath) {
        return dumpModule(modulePath);
    },

    /**
     * Dump all app modules
     */
    dumpAll: function() {
        const appInfo = getAppModules();
        const results = {
            bundlePath: appInfo.bundlePath,
            modules: [],
            dumpedFiles: []
        };

        for (const mod of appInfo.modules) {
            console.log(`\n[*] Processing: ${mod.name}`);
            const dumpedPath = dumpModule(mod.path);

            results.modules.push({
                name: mod.name,
                originalPath: mod.path,
                dumpedPath: dumpedPath,
                success: dumpedPath !== null
            });

            if (dumpedPath) {
                results.dumpedFiles.push(dumpedPath);
            }
        }

        console.log(`\n[+] Dump complete: ${results.dumpedFiles.length}/${results.modules.length} modules`);
        return results;
    },

    /**
     * Get app bundle path
     */
    getBundlePath: function() {
        if (typeof ObjC !== 'undefined' && ObjC.available) {
            return ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
        }
        // Fallback: return path of first module
        const modules = Process.enumerateModules();
        if (modules.length > 0) {
            return modules[0].path.substring(0, modules[0].path.lastIndexOf('/'));
        }
        return null;
    }
};

console.log('[*] Modern iOS Dumper Agent loaded');
