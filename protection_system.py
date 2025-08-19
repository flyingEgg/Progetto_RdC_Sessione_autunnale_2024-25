import json
from collections import defaultdict, Counter

try:
    from pyopnsense import configure
    from pyopnsense.client import ApiClient

    PYOPNSENSE_AVAILABLE = True
    print("Auto-blocking abilitato")
except ImportError:
    PYOPNSENSE_AVAILABLE = False
    print("Solo analisi")


class RealTimeProtectionSystem:
    def __init__(self, syslog_port: "514", opnsense_host_addr="192.168.1.83"):
        self.syslog_port = syslog_port
        self.syslog_socket = None
        self.running = False

        self.opnsense_host_addr = opnsense_host_addr
        self.opnsense_client_addr = None

        # Datasets per behavioural analysis
        self.ip_alerts = defaultdict(list)
        self.ip_attack_types = defaultdict(Counter)
        self.blocked_ips = set()

        self.TIME_WINDOW = 300  # 5 minuti
        self.ALERT_THREESHOLD = 10  # nr. max di alert entro la time window
        self.SUSPICIOUS_KEYWORDS = [
            'scan', 'brute', 'trojan',
            'attack', 'malware', 'exploit',
            'intrusion', 'nmap', 'flood',
            'brute force', 'DOS', 'port scan'
        ]

    # stdin, stdout, stderr = ssh_client.exec_command("tail -n 100 /var/log/suricata/eve.json")
    # log_data = stdout.read().decode()
    #
    # print(log_data)
    # decoded_log_data = json.loads(log_data)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Sistema di protezione ed analisi comportamentale in tempo reale')

    parser.add_argument('--port', type=int, help='Porta syslog (default: 514)', default=514)
    parser.add_argument('--host', help='Indirizzo IP di OPNsense (default: 192.168.54.1)', default='192.168.54.1')
    parser.add_argument('--treeshold', type=int, help='Soglia di tempo alert (default: 5 min/300 sec)', default=300)

    args = parser.parse_args()

    protection_sys = RealTimeProtectionSystem(syslog_port=args.port, opnsense_host_addr=args.host)

    protection_sys.ALERT_THREESHOLD = args.treeshold

    print(args.port, args.host)
