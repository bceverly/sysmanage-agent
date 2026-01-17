"""KVM/libvirt VM creation operations using cloud-init for Linux hosts."""

import asyncio
import hashlib
import os
import shutil
import socket
import subprocess  # nosec B404 # Required for system command execution
import tempfile
import time
from typing import Any, Dict, Optional

from src.i18n import _
from src.sysmanage_agent.core.agent_utils import run_command_async
from src.sysmanage_agent.operations.child_host_kvm_cloudinit import KvmCloudInit
from src.sysmanage_agent.operations.child_host_kvm_freebsd import FreeBSDProvisioner
from src.sysmanage_agent.operations.child_host_kvm_types import KvmVmConfig

# Default paths
KVM_IMAGES_DIR = "/var/lib/libvirt/images"
KVM_CLOUDINIT_DIR = "/var/lib/libvirt/cloud-init"


class KvmCreation:
    """KVM/libvirt VM creation operations."""

    def __init__(self, logger):
        """
        Initialize KVM creation operations.

        Args:
            logger: Logger instance
        """
        self.logger = logger
        self._cloudinit = KvmCloudInit(logger)
        self._freebsd = FreeBSDProvisioner(logger)

    def _is_freebsd(self, config: KvmVmConfig) -> bool:
        """
        Check if the distribution is FreeBSD.

        Args:
            config: VM configuration

        Returns:
            True if FreeBSD, False otherwise
        """
        return self._freebsd.is_freebsd(config)

    def _vm_exists(self, vm_name: str) -> bool:
        """
        Check if a VM with the given name already exists.

        Args:
            vm_name: Name of the VM to check

        Returns:
            True if VM exists, False otherwise
        """
        try:
            result = subprocess.run(  # nosec B603 B607
                ["sudo", "virsh", "dominfo", vm_name],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _create_disk_image(
        self, path: str, size: str, disk_format: str = "qcow2"
    ) -> Dict[str, Any]:
        """
        Create a disk image for the VM.

        Args:
            path: Path to create the disk image
            size: Size of the disk (e.g., "20G")
            disk_format: Disk format (qcow2 or raw)

        Returns:
            Dict with success status and message
        """
        try:
            # Ensure parent directory exists
            os.makedirs(os.path.dirname(path), mode=0o755, exist_ok=True)

            self.logger.info(
                _("Creating disk image: %s (%s, %s)"), path, size, disk_format
            )

            result = subprocess.run(  # nosec B603 B607
                ["sudo", "qemu-img", "create", "-f", disk_format, path, size],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": result.stderr
                    or result.stdout
                    or _("Failed to create disk image"),
                }

            return {"success": True, "path": path, "message": _("Disk image created")}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Disk creation timed out")}
        except Exception as error:
            return {"success": False, "error": str(error)}

    def _decompress_xz(self, xz_path: str, output_path: str) -> Dict[str, Any]:
        """
        Decompress an xz-compressed file.

        Args:
            xz_path: Path to the .xz file
            output_path: Path for the decompressed output

        Returns:
            Dict with success status
        """
        try:
            self.logger.info(_("Decompressing xz archive: %s"), xz_path)

            # Use xz with -k to keep the original and -d to decompress
            # Output to stdout and redirect to target file
            result = subprocess.run(  # nosec B603 B607
                ["sudo", "sh", "-c", f"xz -dk -c '{xz_path}' > '{output_path}'"],
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutes for decompression
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": result.stderr or _("Failed to decompress xz archive"),
                }

            self.logger.info(_("Decompressed to: %s"), output_path)
            return {"success": True, "path": output_path}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("xz decompression timed out")}
        except Exception as error:
            return {"success": False, "error": str(error)}

    def _download_cloud_image(self, url: str, dest_path: str) -> Dict[str, Any]:
        """
        Download a cloud image and convert it if necessary.

        Supports compressed formats (.xz) commonly used by FreeBSD.

        Args:
            url: URL of the cloud image
            dest_path: Destination path for the disk

        Returns:
            Dict with success status and path
        """
        try:
            self.logger.info(_("Downloading cloud image from: %s"), url)

            # Create temp download directory
            download_dir = os.path.join(KVM_IMAGES_DIR, ".downloads")
            os.makedirs(download_dir, mode=0o755, exist_ok=True)

            # Generate filename from URL (MD5 used only for cache key, not security)
            url_hash = hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()[:8]
            filename = os.path.basename(url.split("?")[0])
            cached_path = os.path.join(download_dir, f"{url_hash}_{filename}")

            # Determine if this is a compressed file that needs extraction
            is_xz_compressed = filename.endswith(".xz")
            if is_xz_compressed:
                # The cached path is for the compressed file
                # We need a separate path for the decompressed image
                decompressed_filename = filename[:-3]  # Remove .xz suffix
                decompressed_path = os.path.join(
                    download_dir, f"{url_hash}_{decompressed_filename}"
                )
            else:
                decompressed_path = cached_path

            # Check if we have a cached decompressed copy
            if is_xz_compressed and os.path.exists(decompressed_path):
                self.logger.info(
                    _("Using cached decompressed cloud image: %s"), decompressed_path
                )
                cached_path = decompressed_path
            elif not os.path.exists(cached_path):
                # Download the image
                result = subprocess.run(  # nosec B603 B607
                    ["sudo", "curl", "-L", "-o", cached_path, url],
                    capture_output=True,
                    text=True,
                    timeout=1800,  # 30 minutes for large images
                    check=False,
                )

                if result.returncode != 0:
                    return {
                        "success": False,
                        "error": result.stderr or _("Failed to download cloud image"),
                    }

                self.logger.info(_("Cloud image downloaded to: %s"), cached_path)

                # Decompress if needed
                if is_xz_compressed:
                    decompress_result = self._decompress_xz(
                        cached_path, decompressed_path
                    )
                    if not decompress_result.get("success"):
                        return decompress_result
                    # Use the decompressed path going forward
                    cached_path = decompressed_path
            else:
                self.logger.info(_("Using cached cloud image: %s"), cached_path)

            # Create a qcow2 disk with the cloud image as backing file
            self.logger.info(_("Creating disk with cloud image backing file"))
            result = subprocess.run(  # nosec B603 B607
                [
                    "sudo",
                    "qemu-img",
                    "create",
                    "-f",
                    "qcow2",
                    "-F",
                    "qcow2",
                    "-b",
                    cached_path,
                    dest_path,
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

            if result.returncode != 0:
                # Try without backing file format (older qemu-img)
                result = subprocess.run(  # nosec B603 B607
                    [
                        "sudo",
                        "qemu-img",
                        "create",
                        "-f",
                        "qcow2",
                        "-b",
                        cached_path,
                        dest_path,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )

            if result.returncode != 0:
                # Fallback: copy and resize the image directly
                self.logger.info(_("Using direct copy instead of backing file"))
                shutil.copy2(cached_path, dest_path)
                subprocess.run(  # nosec B603 B607
                    ["sudo", "chown", "libvirt-qemu:kvm", dest_path],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )

            return {
                "success": True,
                "path": dest_path,
                "message": _("Cloud image ready"),
            }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("Cloud image download timed out")}
        except Exception as error:
            self.logger.error(_("Error downloading cloud image: %s"), error)
            return {"success": False, "error": str(error)}

    def _resize_disk(self, disk_path: str, size: str) -> Dict[str, Any]:
        """
        Resize a disk image.

        Args:
            disk_path: Path to the disk image
            size: New size (e.g., "20G")

        Returns:
            Dict with success status
        """
        try:
            result = subprocess.run(  # nosec B603 B607
                ["sudo", "qemu-img", "resize", disk_path, size],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": result.stderr or _("Failed to resize disk"),
                }

            return {"success": True, "message": _("Disk resized")}

        except Exception as error:
            return {"success": False, "error": str(error)}

    def _generate_domain_xml(self, config: KvmVmConfig) -> str:
        """
        Generate libvirt domain XML for the VM.

        Args:
            config: VM configuration

        Returns:
            Domain XML as string
        """
        memory_mb = config.get_memory_mb()

        # Build cloud-init disk section if applicable
        cloudinit_disk = ""
        if config.cloud_init_iso_path and os.path.exists(config.cloud_init_iso_path):
            cloudinit_disk = f"""
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='{config.cloud_init_iso_path}'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>"""

        return f"""<domain type='kvm'>
  <name>{config.vm_name}</name>
  <memory unit='MiB'>{memory_mb}</memory>
  <vcpu>{config.cpus}</vcpu>
  <os>
    <type arch='x86_64'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <cpu mode='host-passthrough'/>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='{config.disk_path}'/>
      <target dev='vda' bus='virtio'/>
    </disk>{cloudinit_disk}
    <interface type='network'>
      <source network='{config.network}'/>
      <model type='virtio'/>
    </interface>
    <serial type='pty'>
      <target port='0'/>
    </serial>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <graphics type='vnc' port='-1' autoport='yes' listen='127.0.0.1'>
      <listen type='address' address='127.0.0.1'/>
    </graphics>
    <video>
      <model type='virtio'/>
    </video>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>
  </devices>
</domain>"""

    def _define_and_start_vm(self, config: KvmVmConfig) -> Dict[str, Any]:
        """
        Define and start the VM using virsh.

        Args:
            config: VM configuration

        Returns:
            Dict with success status
        """
        try:
            # Generate domain XML
            domain_xml = self._generate_domain_xml(config)

            # Write XML to temp file
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".xml", delete=False
            ) as xml_file:
                xml_file.write(domain_xml)
                xml_path = xml_file.name

            try:
                # Define the VM
                self.logger.info(_("Defining VM: %s"), config.vm_name)
                define_result = subprocess.run(  # nosec B603 B607
                    ["sudo", "virsh", "define", xml_path],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )

                if define_result.returncode != 0:
                    return {
                        "success": False,
                        "error": define_result.stderr or _("Failed to define VM"),
                    }

                # Start the VM
                self.logger.info(_("Starting VM: %s"), config.vm_name)
                start_result = subprocess.run(  # nosec B603 B607
                    ["sudo", "virsh", "start", config.vm_name],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )

                if start_result.returncode != 0:
                    return {
                        "success": False,
                        "error": start_result.stderr or _("Failed to start VM"),
                    }

                return {"success": True, "message": _("VM defined and started")}

            finally:
                # Clean up temp XML file
                try:
                    os.unlink(xml_path)
                except (
                    Exception
                ):  # nosec B110 # Expected: continue even if temp file cleanup fails
                    pass

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("VM start timed out")}
        except Exception as error:
            return {"success": False, "error": str(error)}

    def _extract_ip_from_domifaddr(self, output: str) -> Optional[str]:
        """Extract IP address from virsh domifaddr output."""
        for line in output.split("\n"):
            if "ipv4" not in line.lower():
                continue
            for part in line.split():
                if "/" in part and "." in part:
                    ip_addr = part.split("/")[0]
                    if ip_addr and ip_addr != "127.0.0.1":
                        return ip_addr
        return None

    def _extract_ip_from_dhcp_leases(self, output: str, vm_name: str) -> Optional[str]:
        """Extract IP address from virsh net-dhcp-leases output."""
        for line in output.split("\n"):
            if vm_name.lower() not in line.lower():
                continue
            for part in line.split():
                if "." in part and "/" in part:
                    return part.split("/")[0]
        return None

    def _get_vm_ip_once(self, vm_name: str) -> Optional[str]:
        """Try to get VM IP address once from virsh commands."""
        # Try virsh domifaddr
        try:
            result = subprocess.run(  # nosec B603 B607
                ["sudo", "virsh", "domifaddr", vm_name],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                ip_addr = self._extract_ip_from_domifaddr(result.stdout)
                if ip_addr:
                    return ip_addr
        except Exception:  # nosec B110 # Expected: try alternate IP detection method
            pass

        # Try DHCP leases as fallback
        try:
            result = subprocess.run(  # nosec B603 B607
                ["sudo", "virsh", "net-dhcp-leases", "default"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode == 0:
                ip_addr = self._extract_ip_from_dhcp_leases(result.stdout, vm_name)
                if ip_addr:
                    return ip_addr
        except Exception:  # nosec B110 # Expected: return None if no IP found
            pass

        return None

    async def _wait_for_vm_ip(
        self, vm_name: str, timeout: int = 300, interval: int = 5
    ) -> Optional[str]:
        """
        Wait for the VM to get an IP address.

        Args:
            vm_name: Name of the VM
            timeout: Maximum time to wait in seconds
            interval: Time between checks in seconds

        Returns:
            IP address if found, None otherwise
        """
        self.logger.info(_("Waiting for VM %s to get IP address..."), vm_name)
        start_time = time.time()

        while time.time() - start_time < timeout:
            ip_addr = self._get_vm_ip_once(vm_name)
            if ip_addr:
                self.logger.info(_("VM %s has IP: %s"), vm_name, ip_addr)
                return ip_addr
            await asyncio.sleep(interval)

        self.logger.warning(_("Timeout waiting for VM %s to get IP"), vm_name)
        return None

    async def _wait_for_ssh(
        self, ip: str, port: int = 22, timeout: int = 180, interval: int = 5
    ) -> bool:
        """
        Wait for SSH to become available on the VM.

        Args:
            ip: IP address of the VM
            port: SSH port
            timeout: Maximum time to wait in seconds
            interval: Time between checks in seconds

        Returns:
            True if SSH is available, False otherwise
        """
        self.logger.info(_("Waiting for SSH on %s:%d..."), ip, port)
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((ip, port))
                sock.close()

                if result == 0:
                    self.logger.info(_("SSH is available on %s"), ip)
                    return True
            except Exception:  # nosec B110 # Expected: retry SSH check
                pass

            await asyncio.sleep(interval)

        self.logger.warning(_("Timeout waiting for SSH on %s"), ip)
        return False

    async def create_vm(self, config: KvmVmConfig) -> Dict[str, Any]:
        """
        Create a KVM virtual machine with cloud-init.

        Args:
            config: VM configuration

        Returns:
            Dict with success status and VM details
        """
        try:
            self.logger.info(_("Creating KVM VM: %s"), config.vm_name)

            # Step 1: Check if VM already exists
            if self._vm_exists(config.vm_name):
                return {
                    "success": False,
                    "error": _("VM '%s' already exists") % config.vm_name,
                }

            # Step 2: Set up disk path
            disk_filename = f"{config.vm_name}.qcow2"
            config.disk_path = os.path.join(KVM_IMAGES_DIR, disk_filename)

            # Step 3: Download/prepare cloud image or create empty disk
            if config.cloud_image_url:
                self.logger.info(_("Preparing cloud image"))
                disk_result = self._download_cloud_image(
                    config.cloud_image_url, config.disk_path
                )
                if not disk_result.get("success"):
                    return disk_result

                # Resize the disk to the requested size
                resize_result = self._resize_disk(config.disk_path, config.disk_size)
                if not resize_result.get("success"):
                    self.logger.warning(
                        _("Could not resize disk: %s"), resize_result.get("error")
                    )
            else:
                # Create empty disk
                disk_result = self._create_disk_image(
                    config.disk_path, config.disk_size, config.disk_format
                )
                if not disk_result.get("success"):
                    return disk_result

            # Step 4: Provision the VM (cloud-init for Linux, config disk for FreeBSD)
            if config.use_cloud_init:
                if self._is_freebsd(config):
                    # FreeBSD: Create config disk with cloud-init compatible format
                    self.logger.info(_("Provisioning FreeBSD with config disk"))
                    freebsd_result = self._freebsd.provision_image(
                        config.disk_path, config
                    )
                    if not freebsd_result.get("success"):
                        return freebsd_result
                    # Set cloud_init_iso_path to the FreeBSD config disk
                    config.cloud_init_iso_path = freebsd_result.get("config_disk_path")
                else:
                    # Linux: Use cloud-init ISO
                    self.logger.info(_("Creating cloud-init ISO"))
                    cloudinit_result = self._cloudinit.create_cloud_init_iso(config)
                    if not cloudinit_result.get("success"):
                        return cloudinit_result

            # Step 5: Define and start VM
            self.logger.info(_("Defining and starting VM"))
            start_result = self._define_and_start_vm(config)
            if not start_result.get("success"):
                return start_result

            # Step 6: Wait for VM to get IP
            vm_ip = await self._wait_for_vm_ip(config.vm_name)
            if not vm_ip:
                self.logger.warning(_("VM started but could not get IP address"))
                return {
                    "success": True,
                    "message": _("VM created but IP address not yet available"),
                    "vm_name": config.vm_name,
                    "status": "running",
                    "ip_pending": True,
                }

            # Step 7: Wait for SSH (cloud-init needs time to run)
            ssh_available = await self._wait_for_ssh(vm_ip)
            if not ssh_available:
                self.logger.warning(_("VM running but SSH not available yet"))
                return {
                    "success": True,
                    "message": _("VM created, cloud-init may still be running"),
                    "vm_name": config.vm_name,
                    "status": "running",
                    "ip_address": vm_ip,
                    "ssh_pending": True,
                }

            # Step 8: For FreeBSD, run the bootstrap script automatically
            if self._is_freebsd(config) and self._freebsd.has_ssh_key():
                self.logger.info(_("Running FreeBSD bootstrap script"))
                bootstrap_result = await self._freebsd.run_bootstrap_via_ssh(vm_ip)
                if not bootstrap_result.get("success"):
                    self.logger.warning(
                        _(
                            "FreeBSD bootstrap failed: %s. Manual bootstrap may be required."
                        ),
                        bootstrap_result.get("error"),
                    )
                    # Don't fail the whole operation - VM is created and running
                else:
                    self.logger.info(_("FreeBSD bootstrap completed successfully"))

                # Clean up the temporary SSH key
                self._freebsd.cleanup()

            self.logger.info(
                _("KVM VM '%s' created successfully at %s"), config.vm_name, vm_ip
            )
            return {
                "success": True,
                "message": _("VM created successfully"),
                "vm_name": config.vm_name,
                "status": "running",
                "ip_address": vm_ip,
                "child_name": config.vm_name,
                "child_type": "kvm",
            }

        except Exception as error:
            self.logger.error(_("Error creating KVM VM: %s"), error)
            # Try to clean up on failure
            try:
                if self._vm_exists(config.vm_name):
                    await run_command_async(
                        ["sudo", "virsh", "destroy", config.vm_name],
                        timeout=30,
                    )
                    await run_command_async(
                        [
                            "sudo",
                            "virsh",
                            "undefine",
                            config.vm_name,
                            "--remove-all-storage",
                        ],
                        timeout=30,
                    )
            except Exception:  # nosec B110 # Expected: cleanup is best-effort
                pass
            return {"success": False, "error": str(error)}

    def list_vms(self) -> Dict[str, Any]:
        """
        List all KVM virtual machines.

        Returns:
            Dict with success status and list of VMs
        """
        try:
            result = subprocess.run(  # nosec B603 B607
                ["sudo", "virsh", "list", "--all"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": result.stderr or _("Failed to list VMs"),
                }

            vms = []
            lines = result.stdout.strip().split("\n")
            # Skip header lines
            for line in lines[2:]:
                parts = line.split()
                if len(parts) >= 2:
                    vm_id = parts[0] if parts[0] != "-" else None
                    vm_name = parts[1]
                    vm_state = " ".join(parts[2:]) if len(parts) > 2 else "unknown"

                    # Get more details
                    vm_info = self._get_vm_info(vm_name)

                    vms.append(
                        {
                            "name": vm_name,
                            "id": vm_id,
                            "state": vm_state,
                            "child_type": "kvm",
                            **vm_info,
                        }
                    )

            return {"success": True, "vms": vms}

        except subprocess.TimeoutExpired:
            return {"success": False, "error": _("List VMs timed out")}
        except Exception as error:
            return {"success": False, "error": str(error)}

    def _parse_dominfo_output(self, output: str) -> Dict[str, Any]:
        """Parse virsh dominfo output into a dictionary."""
        info = {}
        wanted_keys = {"state", "max_memory", "used_memory", "cpu(s)", "autostart"}
        for line in output.split("\n"):
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower().replace(" ", "_")
            if key in wanted_keys:
                info[key] = value.strip()
        return info

    def _get_vm_info(self, vm_name: str) -> Dict[str, Any]:
        """
        Get detailed information about a VM.

        Args:
            vm_name: Name of the VM

        Returns:
            Dict with VM details
        """
        info = {}

        try:
            # Get basic info
            result = subprocess.run(  # nosec B603 B607
                ["sudo", "virsh", "dominfo", vm_name],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if result.returncode == 0:
                info = self._parse_dominfo_output(result.stdout)

            # Try to get IP address
            ip_result = subprocess.run(  # nosec B603 B607
                ["sudo", "virsh", "domifaddr", vm_name],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            if ip_result.returncode == 0:
                ip_addr = self._extract_ip_from_domifaddr(ip_result.stdout)
                if ip_addr:
                    info["ip_address"] = ip_addr

        except Exception:  # nosec B110 # Optional: IP address retrieval can fail
            pass

        return info
