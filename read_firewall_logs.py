import re
from collections import defaultdict
import geoip2.database
import requests
from datetime import datetime, timedelta


class ThreatIntelAPI:
    """Actual implementation of threat intelligence service"""

    def __init__(self):
        
        self.cache = {}
        self.cache_expiry = timedelta(hours=1)

        # Free tier threat intelligence sources
        self.sources = {
            'abuseipdb': {
                'url': 'https://api.abuseipdb.com/api/v2/check',
                'headers': {'Key': 'YOUR_API_KEY', 'Accept': 'application/json'}
            },
            'virustotal': {
                'url': 'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                'headers': {'x-apikey': 'YOUR_API_KEY'}
            },
            'greynoise': {
                'url': 'https://api.greynoise.io/v3/community/{ip}',
                'headers': {'key': 'YOUR_API_KEY'}
            }
        }

    def lookup(self, ip):
        """Check IP against multiple threat feeds"""
        if ip in self.cache and datetime.now() - self.cache[ip]['timestamp'] < self.cache_expiry:
            return self.cache[ip]['data']

        result = {
            'ip': ip,
            'malicious': False,
            'threat_types': [],
            'confidence': 0,
            'sources': []
        }

        # Check AbuseIPDB
        try:
            abuseipdb_response = requests.get(
                self.sources['abuseipdb']['url'],
                headers=self.sources['abuseipdb']['headers'],
                params={'ipAddress': ip, 'maxAgeInDays': 90}
            )
            if abuseipdb_response.status_code == 200:
                data = abuseipdb_response.json()['data']
                if data['abuseConfidenceScore'] > 0:
                    result['malicious'] = True
                    result['threat_types'].append(data['usageType'] or 'malicious')
                    result['confidence'] = max(result['confidence'], data['abuseConfidenceScore'])
                    result['sources'].append('abuseipdb')
        except Exception as e:
            pass

        # Check VirusTotal
        try:
            virustotal_response = requests.get(
                self.sources['virustotal']['url'].format(ip=ip),
                headers=self.sources['virustotal']['headers']
            )
            if virustotal_response.status_code == 200:
                data = virustotal_response.json()
                if 'data' in data and 'attributes' in data['data']:
                    if data['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                        result['malicious'] = True
                        result['threat_types'].extend(
                            k for k, v in data['data']['attributes']['last_analysis_results'].items()
                            if v['category'] == 'malicious'
                        )
                        result['confidence'] = max(
                            result['confidence'],
                            data['data']['attributes']['last_analysis_stats']['malicious'] * 10
                        )
                        result['sources'].append('virustotal')
        except Exception as e:
            pass

        # Cache the result
        self.cache[ip] = {
            'timestamp': datetime.now(),
            'data': result
        }

        return result


class FirewallAnalyzer:
    def __init__(self):
        self.threat_intel = ThreatIntelAPI()
        try:
            self.geoip_reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        except:
            self.geoip_reader = None

        # Basic firewall patterns (simplified from previous example)
        self.patterns = {
            'src_ip': re.compile(r'SRC=(\d+\.\d+\.\d+\.\d+)'),
            'dst_port': re.compile(r'DPT=(\d+)'),
            'action': re.compile(r'(DROP|REJECT|DENY|ALLOW|ACCEPT)')
        }

    def analyze(self, log_file):
        results = {
            'stats': {'total': 0, 'blocked': 0},
            'threats': defaultdict(list),
            'top_ports': defaultdict(int),
            'recommendations': []
        }

        with open(log_file, 'r') as f:
            for line in f:
                results['stats']['total'] += 1

                # Basic parsing
                src_ip = self._extract_pattern(line, 'src_ip')
                dst_port = self._extract_pattern(line, 'dst_port')
                action = self._extract_pattern(line, 'action')

                if not src_ip:
                    continue

                if action and 'DROP' in action:
                    results['stats']['blocked'] += 1

                    # Threat intelligence check
                    ti_data = self.threat_intel.lookup(src_ip)
                    if ti_data['malicious']:
                        results['threats']['known_malicious'].append({
                            'ip': src_ip,
                            'threat_types': ti_data['threat_types'],
                            'confidence': ti_data['confidence']
                        })

                    # Port analysis
                    if dst_port:
                        results['top_ports'][dst_port] += 1

                        # Check for suspicious ports
                        if int(dst_port) in [4444, 5555, 6666, 31337]:
                            results['threats']['suspicious_ports'].append({
                                'ip': src_ip,
                                'port': dst_port
                            })

        # Generate recommendations
        if len(results['threats']['known_malicious']) > 5:
            results['recommendations'].append(
                "Consider implementing automated IP blocking for known malicious hosts"
            )

        if len(results['threats']['suspicious_ports']) > 3:
            results['recommendations'].append(
                "Review firewall rules for ports: " +
                ", ".join(set(str(t['port']) for t in results['threats']['suspicious_ports']))
            )

        return results

    def _extract_pattern(self, line, pattern_type):
        match = self.patterns[pattern_type].search(line)
        return match.group(1) if match else None


# Example usage
if __name__ == "__main__":
    analyzer = FirewallAnalyzer()
    results = analyzer.analyze('firewall.log')

    print("Analysis Results:")
    print(f"Total entries: {results['stats']['total']}")
    print(f"Blocked entries: {results['stats']['blocked']}")
    print("\nThreats detected:")
    for threat_type, entries in results['threats'].items():
        print(f"- {threat_type}: {len(entries)} cases")

    print("\nRecommendations:")
    for rec in results['recommendations']:
        print(f"- {rec}")