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
 * Dump a loaded module's decrypted memory to disk
 */
function dumpModule(modulePath) {
    console.log(`[*] Dumping: ${modulePath}`);

    try {
        // Find the module by name
        const moduleName = modulePath.split('/').pop();
        const module = Process.findModuleByName(moduleName);

        if (!module) {
            console.log(`[!] Module not found: ${moduleName}`);
            return null;
        }

        // Read the entire module from memory
        const baseAddress = module.base;
        const moduleSize = module.size;

        console.log(`[*] Base: ${baseAddress}, Size: ${moduleSize} bytes`);

        // Read decrypted memory
        // NOTE: Memory.readByteArray is undefined in Frida 17.5.2
        // Use NativePointer.readByteArray instead
        console.log(`[*] Reading memory...`);
        const decryptedData = baseAddress.readByteArray(moduleSize);
        console.log(`[*] Memory read complete`);

        if (!decryptedData) {
            console.log(`[!] Failed to read memory for ${modulePath}`);
            return null;
        }

        // Convert ArrayBuffer to byte array for patching
        console.log(`[*] Converting to byte array for patching...`);
        const byteArray = new Uint8Array(decryptedData);

        // Patch the cryptid in the Mach-O header
        console.log(`[*] Patching Mach-O header...`);
        const patched = patchCryptid(byteArray);

        if (!patched) {
            console.log(`[!] Warning: Failed to patch cryptid, but continuing...`);
        }

        // Create output path in /tmp
        const outputPath = `/tmp/${modulePath.split('/').pop()}.decrypted`;

        // Try File API first, fallback to POSIX if unavailable
        if (FILE_API_AVAILABLE) {
            try {
                const file = new File(outputPath, 'wb');
                // Write the modified byte array
                file.write(byteArray.buffer);
                file.close();
            } catch (fileError) {
                console.log(`[!] File API failed: ${fileError.message}, trying POSIX fallback`);
                // Fall through to POSIX method
                if (!writePOSIX(outputPath, byteArray.buffer)) {
                    return null;
                }
            }
        } else {
            // Use POSIX fallback
            if (!writePOSIX(outputPath, byteArray.buffer)) {
                return null;
            }
        }

        console.log(`[+] Dumped to: ${outputPath}`);
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
