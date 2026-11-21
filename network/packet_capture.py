"""
Live Packet Capture Engine using TShark / Wireshark
Handles interface detection, background packet capture, process supervision,
and PCAP file management without blocking Flask execution.
"""

import os
import sys
import time
import shutil
import subprocess
import threading
from typing import List, Dict, Any, Optional

try:
    import psutil
except ImportError:
    psutil = None

DEFAULT_TSHARK_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "/usr/bin/tshark",
    "/usr/local/bin/tshark",
]

CAPTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "captures")


class PacketCaptureEngine:
    """
    Manages live packet capture using the installed TShark binary.
    Executes capture as an asynchronous background subprocess.
    """

    def __init__(self, custom_tshark_path: Optional[str] = None):
        self.tshark_path = self._detect_tshark(custom_tshark_path)
        self.process: Optional[subprocess.Popen] = None
        self.is_capturing = False
        self.current_interface: Optional[str] = None
        self.current_filter: Optional[str] = None
        self.current_output_file: Optional[str] = None
        self.start_time: Optional[float] = None
        self.lock = threading.Lock()
        os.makedirs(CAPTURES_DIR, exist_ok=True)

    def _detect_tshark(self, custom_path: Optional[str] = None) -> Optional[str]:
        """Detects the TShark executable path."""
        if custom_path and os.path.exists(custom_path):
            return custom_path

        env_path = os.environ.get("TSHARK_PATH")
        if env_path and os.path.exists(env_path):
            return env_path

        which_tshark = shutil.which("tshark")
        if which_tshark and os.path.exists(which_tshark):
            return which_tshark

        for path in DEFAULT_TSHARK_PATHS:
            if os.path.exists(path):
                return path

        return None

    def is_available(self) -> bool:
        """Returns True if TShark is detected and executable."""
        return self.tshark_path is not None and os.path.exists(self.tshark_path)

    def list_interfaces(self) -> List[Dict[str, Any]]:
        """
        Enumerates available network capture interfaces via TShark.
        Falls back to psutil or localhost stub if unavailable.
        """
        interfaces = []
        if not self.is_available():
            return [{
                "id": "1",
                "device": "127.0.0.1",
                "name": "Loopback (TShark Not Installed - Simulated Mode)",
                "is_loopback": True,
            }]

        try:
            cmd = [self.tshark_path, "-D"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5.0)
            if res.returncode == 0:
                for line in res.stdout.strip().splitlines():
                    parts = line.strip().split(" ", 2)
                    if len(parts) >= 2:
                        idx = parts[0].rstrip(".")
                        dev = parts[1]
                        desc = parts[2].strip("()") if len(parts) > 2 else dev
                        is_loop = "loopback" in dev.lower() or "loopback" in desc.lower()
                        interfaces.append({
                            "id": idx,
                            "device": dev,
                            "name": desc,
                            "is_loopback": is_loop,
                        })
        except Exception as e:
            interfaces.append({
                "id": "1",
                "device": "\\Device\\NPF_Loopback",
                "name": f"Loopback (Detection error: {str(e)})",
                "is_loopback": True,
            })

        return interfaces

    def get_default_loopback_interface(self) -> str:
        """Finds the loopback interface ID or device string."""
        for iface in self.list_interfaces():
            if iface.get("is_loopback"):
                return iface.get("device") or iface.get("id")
        return "1"

    def start_capture(self, interface: Optional[str] = None,
                      capture_filter: str = "tcp port 5000 or tcp port 5443",
                      output_filename: Optional[str] = None) -> Dict[str, Any]:
        """
        Starts a background TShark packet capture process.
        Safe execution with argument list (avoids shell=True).
        """
        with self.lock:
            if self.is_capturing:
                return {
                    "success": False,
                    "message": "A capture session is already in progress.",
                    "status": self.get_status(),
                }

            if not self.is_available():
                return {
                    "success": False,
                    "message": "TShark executable not found. Please install Wireshark with TShark.",
                    "status": {"is_available": False},
                }

            if not interface:
                interface = self.get_default_loopback_interface()

            known = self.list_interfaces()
            if known and str(interface) not in {str(i.get("id")) for i in known} | {str(i.get("device")) for i in known}:
                return {
                    "success": False,
                    "message": f"Unknown capture interface '{interface}'. Choose one of the listed interfaces.",
                }

            if not output_filename:
                timestamp_str = time.strftime("%Y%m%d_%H%M%S")
                output_filename = f"capture_{timestamp_str}.pcapng"

            output_path = os.path.join(CAPTURES_DIR, output_filename)

            cmd = [
                self.tshark_path,
                "-i", interface,
                "-f", capture_filter,
                "-w", output_path,
            ]

            try:
                # Spawn background subprocess with no window on Windows
                creation_flags = 0
                if sys.platform == "win32":
                    creation_flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0x08000000

                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=creation_flags,
                )
                time.sleep(0.8)   # a capture that cannot start (bad interface, no permission) exits immediately
                if self.process.poll() is not None:
                    err = ""
                    try:
                        err = (self.process.stderr.read() or b"").decode("utf-8", "replace").strip()
                    except Exception:
                        pass
                    self.process = None
                    self.is_capturing = False
                    return {
                        "success": False,
                        "message": "Capture could not start (missing permission or interface unavailable): " + err[-300:],
                    }
                self.is_capturing = True
                self.current_interface = interface
                self.current_filter = capture_filter
                self.current_output_file = output_path
                self.start_time = time.time()

                return {
                    "success": True,
                    "message": f"Packet capture started on interface '{interface}'",
                    "interface": interface,
                    "filter": capture_filter,
                    "output_file": output_path,
                    "start_time": self.start_time,
                }
            except Exception as e:
                self.is_capturing = False
                return {
                    "success": False,
                    "message": f"Failed to start packet capture: {str(e)}",
                }

    def stop_capture(self) -> Dict[str, Any]:
        """Stops the active capture session gracefully."""
        with self.lock:
            if not self.is_capturing or not self.process:
                return {
                    "success": False,
                    "message": "No active packet capture to stop.",
                }

            duration = time.time() - (self.start_time or time.time())
            output_file = self.current_output_file

            try:
                if self.process.stdout:
                    self.process.stdout.close()
                if self.process.stderr:
                    self.process.stderr.close()
                children = []
                if psutil is not None:
                    try:
                        children = psutil.Process(self.process.pid).children(recursive=True)
                    except Exception:
                        children = []
                self.process.terminate()
                for child in children:          # tshark spawns dumpcap; stop it too so the file is flushed and closed
                    try:
                        child.terminate()
                    except Exception:
                        pass
                self.process.wait(timeout=3.0)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass

            self.is_capturing = False
            self.process = None

            # Get captured file size
            file_size_bytes = 0
            if output_file and os.path.exists(output_file):
                file_size_bytes = os.path.getsize(output_file)

            return {
                "success": True,
                "message": "Packet capture stopped successfully.",
                "duration_seconds": round(duration, 2),
                "output_file": output_file,
                "file_size_bytes": file_size_bytes,
            }

    def get_status(self) -> Dict[str, Any]:
        """Returns the current state of the capture engine."""
        duration = 0.0
        if self.is_capturing and self.start_time:
            duration = round(time.time() - self.start_time, 2)

        file_size_bytes = 0
        if self.current_output_file and os.path.exists(self.current_output_file):
            file_size_bytes = os.path.getsize(self.current_output_file)

        return {
            "is_available": self.is_available(),
            "tshark_path": self.tshark_path,
            "is_capturing": self.is_capturing,
            "interface": self.current_interface,
            "filter": self.current_filter,
            "output_file": self.current_output_file,
            "duration_seconds": duration,
            "file_size_bytes": file_size_bytes,
        }


# Singleton instance
_GLOBAL_ENGINE: Optional[PacketCaptureEngine] = None

def get_capture_engine() -> PacketCaptureEngine:
    global _GLOBAL_ENGINE
    if _GLOBAL_ENGINE is None:
        _GLOBAL_ENGINE = PacketCaptureEngine()
    return _GLOBAL_ENGINE
