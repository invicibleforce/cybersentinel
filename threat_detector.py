from collections import defaultdict
import pandas as pd
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class ThreatDetector:

    def __init__(self):
        self.alerts = []
        self.connection_tracker = defaultdict(lambda: {
            'ports':      set(),
            'count':      0,
            'first_seen': None,
            'last_seen':  None,
        })

    def detect_port_scan(self, df, threshold=10, time_window=60):
        logger.info("Running port scan detection...")

        if df.empty or 'dest_port' not in df.columns:
            return []

        for source_ip in df['source_ip'].unique():
            ip_traffic      = df[df['source_ip'] == source_ip].copy()
            unique_ports    = ip_traffic['dest_port'].nunique()
            unique_dest_ips = ip_traffic['destination_ip'].nunique()

            if unique_ports >= threshold:
                time_span = (
                    (ip_traffic['timestamp'].max() - ip_traffic['timestamp'].min())
                    .total_seconds()
                    if len(ip_traffic) > 1 else 0
                )
                alert = {
                    'timestamp':       datetime.now(),
                    'type':            'Port Scan',
                    'severity':        'HIGH',
                    'source_ip':       source_ip,
                    'ports_scanned':   int(unique_ports),
                    'targets':         int(unique_dest_ips),
                    'time_span':       f"{time_span:.1f}s",
                    'description':     f'{source_ip} scanned {unique_ports} ports on {unique_dest_ips} hosts',
                    'recommendation':  'Block source IP and investigate potential reconnaissance activity',
                }
                self.alerts.append(alert)
                logger.warning("PORT SCAN: %s", alert['description'])

        return self.alerts

    def detect_ddos(self, df, threshold=50, time_window=10):
        logger.info("Running DDoS detection...")

        if df.empty:
            return []

        for dest_ip in df['destination_ip'].unique():
            dest_traffic    = df[df['destination_ip'] == dest_ip].copy()
            unique_sources  = dest_traffic['source_ip'].nunique()
            packets_per_src = len(dest_traffic) / unique_sources if unique_sources else 0

            if len(dest_traffic) > threshold and unique_sources > 5 and packets_per_src > 10:
                alert = {
                    'timestamp':      datetime.now(),
                    'type':           'DDoS Attack',
                    'severity':       'CRITICAL',
                    'target_ip':      dest_ip,
                    'source_count':   int(unique_sources),
                    'packet_rate':    int(len(dest_traffic)),
                    'description':    f'Potential DDoS: {dest_ip} receiving traffic from {unique_sources} sources',
                    'recommendation': 'Enable rate limiting and consider DDoS mitigation services',
                }
                self.alerts.append(alert)
                logger.critical("DDOS: %s", alert['description'])

        return self.alerts

    def detect_data_exfiltration(self, df, multiplier=3):
        logger.info("Running data exfiltration detection...")

        if df.empty or 'size' not in df.columns:
            return []

        ip_stats = df.groupby('source_ip')['size'].agg(['sum', 'mean', 'count'])
        if ip_stats.empty:
            return []

        avg_total = ip_stats['sum'].mean()

        for ip, stats in ip_stats.iterrows():
            if stats['sum'] > avg_total * multiplier:
                alert = {
                    'timestamp':       datetime.now(),
                    'type':            'Data Exfiltration',
                    'severity':        'HIGH',
                    'source_ip':       ip,
                    'data_sent':       f"{stats['sum']:,} bytes ({stats['sum'] / 1024 / 1024:.2f} MB)",
                    'packet_count':    int(stats['count']),
                    'avg_packet_size': f"{stats['mean']:.0f} bytes",
                    'description':     f'{ip} transferred unusually large amount of data',
                    'recommendation':  'Investigate data transfer patterns and check for unauthorized access',
                }
                self.alerts.append(alert)
                logger.warning("DATA EXFIL: %s", alert['description'])

        return self.alerts

    def detect_suspicious_ports(self, df):
        logger.info("Running suspicious port detection...")

        suspicious_ports = {
            22:    'SSH',
            23:    'Telnet',
            3389:  'RDP',
            1433:  'MSSQL',
            3306:  'MySQL',
            5432:  'PostgreSQL',
            6379:  'Redis',
            27017: 'MongoDB',
            4444:  'Metasploit',
            5555:  'Android Debug',
            8080:  'HTTP Proxy',
            9050:  'Tor',
        }

        if df.empty or 'dest_port' not in df.columns:
            return []

        for port, service in suspicious_ports.items():
            port_traffic   = df[df['dest_port'] == port]
            unique_sources = port_traffic['source_ip'].nunique()

            if not port_traffic.empty and unique_sources > 3:
                alert = {
                    'timestamp':      datetime.now(),
                    'type':           'Suspicious Port Access',
                    'severity':       'MEDIUM',
                    'port':           port,
                    'service':        service,
                    'source_count':   int(unique_sources),
                    'attempt_count':  len(port_traffic),
                    'description':    f'Multiple IPs ({unique_sources}) accessing {service} on port {port}',
                    'recommendation': f'Review {service} access logs and ensure proper authentication',
                }
                self.alerts.append(alert)
                logger.warning("SUSPICIOUS PORT: %s", alert['description'])

        return self.alerts

    def run_all_detections(self, df):
        logger.info("Running comprehensive threat detection...")
        self.alerts = []  # clear previous cycle's alerts

        self.detect_port_scan(df)
        self.detect_ddos(df)
        self.detect_data_exfiltration(df)
        self.detect_suspicious_ports(df)

        logger.info("Detection complete. Total alerts: %d", len(self.alerts))
        return self.alerts

    def get_alerts_dataframe(self):
        if not self.alerts:
            return pd.DataFrame()
        return pd.DataFrame(self.alerts)


if __name__ == "__main__":
    sample_data = pd.DataFrame({
        'timestamp':      [datetime.now()] * 100,
        'source_ip':      ['192.168.1.100'] * 50 + ['192.168.1.101'] * 50,
        'destination_ip': ['10.0.0.1'] * 100,
        'dest_port':      list(range(1, 51)) + [80] * 50,
        'size':           [1500] * 100,
    })

    detector = ThreatDetector()
    alerts   = detector.run_all_detections(sample_data)

    print(f"\n=== Threat Detection Results ===")
    print(f"Alerts generated: {len(alerts)}")
    for alert in alerts:
        print(f"[{alert['severity']}] {alert['type']}: {alert['description']}")