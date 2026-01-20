#!/usr/bin/env python3
"""
Modern iOS IPA Dumper for Frida 17.5.2+
Compatible with iOS 14.7.1 + Taurine jailbreak
"""

import frida
import sys
import os
import argparse
import shutil
import tempfile
from pathlib import Path
import paramiko
from scp import SCPClient


class ModernIOSDumper:
    def __init__(self, device, ssh_host='localhost', ssh_port=2222,
                 ssh_user='root', ssh_password=None):
        self.device = device
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_password = ssh_password

    def get_device(self):
        """Get USB device"""
        try:
            device_manager = frida.get_device_manager()
            devices = device_manager.enumerate_devices()

            # Look for USB device
            for dev in devices:
                if dev.type == 'usb':
                    print(f"[+] Found device: {dev.name}")
                    return dev

            print("[!] No USB device found")
            return None
        except Exception as e:
            print(f"[!] Error getting device: {e}")
            return None

    def list_applications(self):
        """List all installed applications"""
        try:
            apps = self.device.enumerate_applications()

            print("\nInstalled Applications:")
            print("-" * 80)
            print(f"{'PID':<8} {'Name':<30} {'Bundle ID'}")
            print("-" * 80)

            for app in sorted(apps, key=lambda x: (x.pid == 0, x.name)):
                pid_str = str(app.pid) if app.pid != 0 else "-"
                print(f"{pid_str:<8} {app.name:<30} {app.identifier}")

        except Exception as e:
            print(f"[!] Error listing applications: {e}")

    def attach_to_app(self, bundle_id_or_name):
        """Attach to running app or spawn it"""
        try:
            # Find the app
            apps = self.device.enumerate_applications()
            target_app = None

            for app in apps:
                if bundle_id_or_name in (app.identifier, app.name):
                    target_app = app
                    break

            if not target_app:
                print(f"[!] App not found: {bundle_id_or_name}")
                return None, None

            print(f"[*] Target app: {target_app.name} ({target_app.identifier})")

            # Check if running
            if target_app.pid == 0:
                print(f"[*] App not running - please launch it manually first")
                print(f"[*] This is required due to Taurine jailbreak restrictions")
                return None, None

            print(f"[*] App is running with PID: {target_app.pid}")
            print(f"[*] Attaching...")

            session = self.device.attach(target_app.pid)
            print(f"[+] Attached successfully")

            return session, target_app

        except Exception as e:
            print(f"[!] Error attaching: {e}")
            return None, None

    def load_agent(self, session):
        """Load the dumper agent"""
        try:
            # Use original agent (simple memory dump, no cryptid patching)
            script_path = Path(__file__).parent / "agent.js"
            with open(script_path, 'r') as f:
                script_code = f.read()

            script = session.create_script(script_code)
            script.on('message', self.on_message)
            script.load()

            return script

        except Exception as e:
            print(f"[!] Error loading agent: {e}")
            return None

    def on_message(self, message, data):
        """Handle messages from agent"""
        if message['type'] == 'log':
            print(message['payload'])
        elif message['type'] == 'error':
            print(f"[!] Agent error: {message}")

    def get_ssh_client(self):
        """Create and connect SSH client"""
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(
                self.ssh_host,
                port=self.ssh_port,
                username=self.ssh_user,
                password=self.ssh_password,
                timeout=10
            )
            return ssh
        except Exception as e:
            print(f"[!] SSH connection failed: {e}")
            return None

    def dump_app(self, bundle_id_or_name, output_dir=None):
        """Main dump function"""
        try:
            # Attach to app
            session, app = self.attach_to_app(bundle_id_or_name)
            if not session:
                return False

            # Load agent
            print(f"[*] Loading dumper agent...")
            script = self.load_agent(session)
            if not script:
                return False

            print(f"[+] Agent loaded\n")

            # Get app info
            print(f"[*] Analyzing app modules...")
            app_info = script.exports_sync.list_modules()
            bundle_path = app_info['bundlePath']
            modules = app_info['modules']

            print(f"[*] Found {len(modules)} modules to dump:")
            for mod in modules:
                print(f"    - {mod['name']} ({mod['size']} bytes)")

            # Dump all modules
            print(f"\n[*] Starting dump...")
            results = script.exports_sync.dump_all()

            # Create output directory
            if not output_dir:
                output_dir = Path(tempfile.gettempdir()) / f"{app.name}_decrypted"
            else:
                output_dir = Path(output_dir)

            output_dir.mkdir(parents=True, exist_ok=True)
            print(f"\n[*] Output directory: {output_dir}")

            # Establish SSH connection for downloads
            print(f"\n[*] Connecting to device via SSH...")
            ssh = self.get_ssh_client()
            if not ssh:
                print(f"[!] Failed to establish SSH connection")
                return False

            # Download dumped files via SCP
            print(f"\n[*] Downloading decrypted binaries...")
            success_count = 0

            try:
                with SCPClient(ssh.get_transport(), socket_timeout=60) as scp:
                    for mod in results['modules']:
                        if not mod['success'] or not mod['dumpedPath']:
                            print(f"[!] Skipped: {mod['name']}")
                            continue

                        remote_path = mod['dumpedPath']
                        local_path = output_dir / mod['name']

                        try:
                            scp.get(remote_path, str(local_path))
                            file_size = local_path.stat().st_size
                            print(f"[+] Downloaded: {mod['name']} ({file_size} bytes)")
                            success_count += 1
                        except Exception as e:
                            print(f"[!] Error downloading {mod['name']}: {e}")

            except Exception as e:
                print(f"[!] SCP error: {e}")

            # Also download the entire app bundle
            print(f"\n[*] Downloading app bundle...")
            bundle_output = output_dir / f"{app.name}.app"

            try:
                with SCPClient(ssh.get_transport(), socket_timeout=120) as scp:
                    scp.get(results['bundlePath'], str(output_dir), recursive=True)

                # Rename to correct .app name
                downloaded_bundle = output_dir / Path(results['bundlePath']).name
                if downloaded_bundle.exists() and downloaded_bundle != bundle_output:
                    if bundle_output.exists():
                        shutil.rmtree(bundle_output)
                    downloaded_bundle.rename(bundle_output)

                print(f"[+] Downloaded app bundle to: {bundle_output}")

                # Replace encrypted binaries with decrypted ones
                print(f"[*] Replacing encrypted binaries with decrypted versions...")
                for mod in results['modules']:
                    if mod['success']:
                        decrypted_file = output_dir / mod['name']
                        if decrypted_file.exists():
                            # Find the original file in the bundle
                            original_path = Path(mod['originalPath'])
                            relative_path = original_path.relative_to(results['bundlePath'])
                            target_file = bundle_output / relative_path

                            if target_file.exists():
                                shutil.copy2(decrypted_file, target_file)
                                print(f"    [+] Replaced: {relative_path}")

                # Create IPA
                print(f"\n[*] Creating IPA...")
                ipa_path = output_dir.parent / f"{app.name}_decrypted.ipa"
                payload_dir = output_dir / "Payload"
                payload_dir.mkdir(exist_ok=True)

                # Move .app to Payload/
                final_app = payload_dir / f"{app.name}.app"
                if final_app.exists():
                    shutil.rmtree(final_app)
                shutil.move(str(bundle_output), str(final_app))

                # Create zip
                shutil.make_archive(
                    str(ipa_path.with_suffix('')),
                    'zip',
                    output_dir,
                    'Payload'
                )

                # Rename to .ipa
                zip_file = ipa_path.with_suffix('.zip')
                if zip_file.exists():
                    zip_file.rename(ipa_path)

                print(f"[+] IPA created: {ipa_path}")

            except Exception as e:
                print(f"[!] Error downloading bundle: {e}")

            print(f"\n[+] Dump complete!")
            print(f"[+] Decrypted binaries: {success_count}/{len(modules)}")
            print(f"[+] Output: {output_dir}")

            if success_count > 0:
                print(f"\n[*] Binaries are ready for analysis (cryptid automatically set to 0)")
                print(f"[*] Verify with: otool -l {output_dir}/Payload/<App>.app/<App> | grep cryptid")

            ssh.close()
            session.detach()
            return True

        except Exception as e:
            print(f"[!] Error during dump: {e}")
            import traceback
            traceback.print_exc()
            return False


def main():
    parser = argparse.ArgumentParser(
        description='Modern iOS IPA Dumper for Frida 17.5.2+',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -l                           # List installed apps
  %(prog)s com.example.app              # Dump app (must be running)
  %(prog)s -o /path/to/output com.app   # Specify output directory

Requirements:
  - App must be running (launch manually first)
  - SSH access to device via USB (iproxy 2222 22)
  - sshpass if using password authentication
        """
    )

    parser.add_argument('target', nargs='?', help='Bundle ID or app name to dump')
    parser.add_argument('-l', '--list', action='store_true', help='List installed applications')
    parser.add_argument('-o', '--output', help='Output directory')
    parser.add_argument('-H', '--host', default='localhost', help='SSH hostname (default: localhost)')
    parser.add_argument('-p', '--port', type=int, default=2222, help='SSH port (default: 2222)')
    parser.add_argument('-u', '--user', default='root', help='SSH username (default: root)')
    parser.add_argument('-P', '--password', help='SSH password')

    args = parser.parse_args()

    # Get device
    print("[*] Connecting to device...")
    device_manager = frida.get_device_manager()
    devices = [d for d in device_manager.enumerate_devices() if d.type == 'usb']

    if not devices:
        print("[!] No USB device found")
        print("[!] Make sure your device is connected and frida-server is running")
        return 1

    device = devices[0]
    print(f"[+] Connected to: {device.name}")

    dumper = ModernIOSDumper(
        device,
        ssh_host=args.host,
        ssh_port=args.port,
        ssh_user=args.user,
        ssh_password=args.password
    )

    # List apps
    if args.list:
        dumper.list_applications()
        return 0

    # Dump app
    if not args.target:
        parser.print_help()
        return 1

    success = dumper.dump_app(args.target, args.output)
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
