import os
import sys
import platform
import logging

from scapy.all import sniff, IP, TCP, UDP, ICMP
import pandas as pd
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _is_root() -> bool:
    if platform.system() == 'Windows':
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def check_privileges(raise_on_failure: bool = False) -> bool:
    if _is_root():
        return True

    msg = (
        "\n"
        "╔══════════════════════════════════════════════════════════════╗\n"
        "║  Packet capture requires elevated privileges.                ║\n"
        "║                                                              ║\n"
        "║  Linux / macOS  →  sudo python main.py                      ║\n"
        "║  Windows        →  run your terminal as Administrator        ║\n"
        "║                                                              ║\n"
        "║  Alternatively, grant Python the cap_net_raw capability:    ║\n"
        "║    sudo setcap cap_net_raw+ep $(which python3)               ║\n"
        "╚══════════════════════════════════════════════════════════════╝\n"
    )

    if raise_on_failure:
        raise PermissionError(msg)

    logger.error(msg)
    return False


class PacketCapture:

    def __init__(self, auto_check_privileges: bool = True):
        self.packets_data   = []
        self.capture_active = False

        if auto_check_privileges:
            check_privileges(raise_on_failure=False)

    def packet_handler(self, packet):
        try:
            if not packet.haslayer(IP):
                return

            info = {
                'timestamp':      datetime.now(),
                'source_ip':      packet[IP].src,
                'destination_ip': packet[IP].dst,
                'protocol':       packet[IP].proto,
                'size':           len(packet),
                'ttl':            packet[IP].ttl,
            }

            if packet.haslayer(TCP):
                info.update({
                    'source_port':   packet[TCP].sport,
                    'dest_port':     packet[TCP].dport,
                    'tcp_flags':     str(packet[TCP].flags),
                    'protocol_name': 'TCP',
                })
            elif packet.haslayer(UDP):
                info.update({
                    'source_port':   packet[UDP].sport,
                    'dest_port':     packet[UDP].dport,
                    'protocol_name': 'UDP',
                })
            elif packet.haslayer(ICMP):
                info.update({
                    'source_port':   0,
                    'dest_port':     0,
                    'protocol_name': 'ICMP',
                })
            else:
                info.update({
                    'source_port':   0,
                    'dest_port':     0,
                    'protocol_name': 'Other',
                })

            self.packets_data.append(info)

            if len(self.packets_data) % 10 == 0:
                logger.info("Captured %d packets...", len(self.packets_data))

        except Exception as exc:
            logger.error("Error processing packet: %s", exc)

    def start_capture(self, count: int = 100, interface=None, timeout=None) -> pd.DataFrame:
        if not _is_root():
            logger.error("Cannot start capture: insufficient privileges.")
            return pd.DataFrame()

        logger.info("Starting packet capture...")

        try:
            self.capture_active = True
            kwargs = dict(prn=self.packet_handler, iface=interface,
                          timeout=timeout, store=False)
            if count > 0:
                kwargs['count'] = count
            sniff(**kwargs)
            logger.info("Capture complete — %d packets total.", len(self.packets_data))
            return self.get_dataframe()

        except PermissionError:
            logger.error("Permission denied. Run with sudo or as Administrator.")
            return pd.DataFrame()
        except Exception as exc:
            logger.error("Capture error: %s", exc)
            return pd.DataFrame()
        finally:
            self.capture_active = False

    def get_dataframe(self) -> pd.DataFrame:
        if not self.packets_data:
            return pd.DataFrame()
        return pd.DataFrame(self.packets_data)

    def clear_data(self):
        self.packets_data = []
        logger.info("Packet data cleared.")


if __name__ == "__main__":
    capturer = PacketCapture()
    df = capturer.start_capture(count=50)

    if not df.empty:
        print(f"\n=== Captured Packets Summary ===")
        print(f"Total packets : {len(df)}")
        print("\nProtocol distribution:")
        print(df['protocol_name'].value_counts())
        print("\nTop 5 source IPs:")
        print(df['source_ip'].value_counts().head())
    else:
        print("No packets captured (check privileges or interface).")