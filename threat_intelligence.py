import requests
import logging
from typing import Dict, Optional, List

logger = logging.getLogger(__name__)


class ThreatIntelligence:

    def __init__(self, abuseipdb_key=None, virustotal_key=None):
        self.abuseipdb_key  = abuseipdb_key
        self.virustotal_key = virustotal_key
        self.cache = {}  # avoids redundant API calls for the same IP

    def check_ip_abuseipdb(self, ip_address: str) -> Optional[Dict]:
        if ip_address in self.cache:
            return self.cache[ip_address]

        if not self.abuseipdb_key:
            logger.warning("No AbuseIPDB API key provided.")
            return None

        url     = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Key': self.abuseipdb_key, 'Accept': 'application/json'}
        params  = {'ipAddress': ip_address, 'maxAgeInDays': '90', 'verbose': ''}

        try:
            response = requests.get(url, headers=headers, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if 'data' in data:
                    result = {
                        'ip':             ip_address,
                        'abuse_score':    data['data']['abuseConfidenceScore'],
                        'is_malicious':   data['data']['abuseConfidenceScore'] > 50,
                        'total_reports':  data['data']['totalReports'],
                        'country':        data['data'].get('countryCode', 'Unknown'),
                        'isp':            data['data'].get('isp', 'Unknown'),
                        'usage_type':     data['data'].get('usageType', 'Unknown'),
                        'is_whitelisted': data['data'].get('isWhitelisted', False),
                    }
                    self.cache[ip_address] = result
                    if result['is_malicious']:
                        logger.warning("Malicious IP: %s (score: %d)",
                                       ip_address, result['abuse_score'])
                    return result
            else:
                logger.error("AbuseIPDB API error: %s", response.status_code)

        except requests.exceptions.RequestException as e:
            logger.error("AbuseIPDB request failed: %s", e)

        return None

    def check_ip_virustotal(self, ip_address: str) -> Optional[Dict]:
        if not self.virustotal_key:
            logger.warning("No VirusTotal API key provided.")
            return None

        url     = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
        headers = {'x-apikey': self.virustotal_key}

        try:
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                data  = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                return {
                    'ip':               ip_address,
                    'malicious_count':  stats.get('malicious', 0),
                    'suspicious_count': stats.get('suspicious', 0),
                    'clean_count':      stats.get('harmless', 0),
                    'undetected_count': stats.get('undetected', 0),
                    'is_malicious':     stats.get('malicious', 0) > 0,
                    'reputation':       data['data']['attributes'].get('reputation', 0),
                }

        except requests.exceptions.RequestException as e:
            logger.error("VirusTotal request failed: %s", e)

        return None

    def scan_ip_list(self, ip_list: List[str], limit: int = 10) -> List[Dict]:
        malicious_ips = []
        logger.info("Scanning %d IPs...", min(len(ip_list), limit))

        for ip in ip_list[:limit]:
            result = self.check_ip_abuseipdb(ip)
            if result and result['is_malicious']:
                malicious_ips.append(result)

        logger.info("Found %d malicious IPs.", len(malicious_ips))
        return malicious_ips

    def generate_report(self, ip_results: List[Dict]) -> str:
        if not ip_results:
            return "No malicious IPs detected."

        report  = "=" * 60 + "\n"
        report += "THREAT INTELLIGENCE REPORT\n"
        report += "=" * 60 + "\n\n"

        for result in ip_results:
            report += f"IP Address    : {result['ip']}\n"
            report += f"Abuse Score   : {result['abuse_score']}/100\n"
            report += f"Total Reports : {result['total_reports']}\n"
            report += f"Country       : {result.get('country', 'Unknown')}\n"
            report += f"ISP           : {result.get('isp', 'Unknown')}\n"
            report += f"Status        : {'MALICIOUS' if result['is_malicious'] else 'Clean'}\n"
            report += "-" * 60 + "\n\n"

        return report


if __name__ == "__main__":
    threat_intel = ThreatIntelligence()
    print("Testing Threat Intelligence (no API key — demo mode)")
    print("Get a free key at https://www.abuseipdb.com/")