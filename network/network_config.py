"""
Network Configuration & Discovery Module
Manages localhost and LAN operation modes, discovers reachable local IP addresses,
and handles interface configuration.
"""

import os
import socket
from typing import Dict, Any, List


class NetworkConfig:
    """
    Manages host binding, port assignments, and LAN address discovery.
    """

    HTTP_PORT = 5000
    HTTPS_PORT = 5443
    PROXY_PORT = 5080

    def __init__(self, mode: str = None):
        # "LOCALHOST" (bind 127.0.0.1) or "LAN" (bind 0.0.0.0); chosen at start-up with CYBERSHIELD_MODE=LAN
        self.mode = (mode or os.environ.get("CYBERSHIELD_MODE", "LOCALHOST")).upper()

    @staticmethod
    def get_local_ip() -> str:
        """
        Detects the computer's reachable LAN IP address.
        Uses a dummy UDP socket connect to avoid hardcoding.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Does not need to be reachable; returns the routing interface IP
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()
        return ip

    def get_bind_host(self) -> str:
        """Returns the bind host based on the active mode."""
        if self.mode == "LAN":
            return "0.0.0.0"
        return "127.0.0.1"

    def get_config_summary(self) -> Dict[str, Any]:
        """Returns an overview of network configuration and reachable endpoints."""
        lan_ip = self.get_local_ip()
        return {
            "mode": self.mode,
            "bind_host": self.get_bind_host(),
            "loopback_ip": "127.0.0.1",
            "lan_ip": lan_ip,
            "http_port": self.HTTP_PORT,
            "https_port": self.HTTPS_PORT,
            "proxy_port": self.PROXY_PORT,
            "reachable_endpoints": {
                "localhost_http": f"http://127.0.0.1:{self.HTTP_PORT}",
                "localhost_https": f"https://127.0.0.1:{self.HTTPS_PORT}",
                "lan_http": f"http://{lan_ip}:{self.HTTP_PORT}" if lan_ip != "127.0.0.1" else "Not on LAN",
                "lan_https": f"https://{lan_ip}:{self.HTTPS_PORT}" if lan_ip != "127.0.0.1" else "Not on LAN",
            },
            "lan_instructions": (
                f"For two-computer LAN mode: Ensure both computers are on the same Wi-Fi/LAN. "
                f"Configure the client on Computer A to target http://{lan_ip}:{self.HTTP_PORT} or https://{lan_ip}:{self.HTTPS_PORT}. "
                f"Verify Windows Firewall allows incoming connections on ports {self.HTTP_PORT} and {self.HTTPS_PORT}."
            ),
        }


# Global configuration instance
GLOBAL_NETWORK_CONFIG = NetworkConfig()
