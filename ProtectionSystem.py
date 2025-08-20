import json
from collections import defaultdict, Counter
from datetime import datetime

import paramiko


def analyze_events(events):
    from dateutil import parser

    current_time = datetime.now()
    threats = []

    for event in events:
        src_ip = event.get('src_ip')
        if not src_ip:
            continue

        # non so se ignorare ip domestici, ci penserò

        # Parsing del timestamp con conversione in oggetto datetime
        try:
            timestamp_str = event.get('timestamp', '')
            if timestamp_str:
                event_time = parser.isoparse(timestamp_str)
            else:
                event_time = current_time
        except(ValueError, AttributeError):
            event_time = current_time
        # print(event_time)


class ProtectionSystem:
    def __init__(self, ssh_host, ssh_port, ssh_user, ssh_pass):
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_pass = ssh_pass

        # Datasets per behavioural analysis
        self.ip_alerts = defaultdict(list)
        self.ip_attack_types = defaultdict(Counter)

        self.TIME_WINDOW = 300  # 5 minuti
        self.ALERT_THREESHOLD = 10  # nr. max di alert entro la time window
        self.SUSPICIOUS_KEYWORDS = [
            'scan', 'brute', 'trojan',
            'attack', 'malware', 'exploit',
            'intrusion'
        ]

    def connect_ssh(self):
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(self.ssh_host, self.ssh_port, self.ssh_user, self.ssh_pass)
            print("Connesso ad SSH")
            return True
        except Exception as e:
            print(f"Errore di connessione ad SSH: {e}")
            return False

    def fetch_recent_events(self, lines=200):
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(f"tail -n {lines} /var/log/suricata/eve.json")

            events = []
            for line in stdout:
                try:
                    event = json.loads(line.strip())
                    events.append(event)
                except json.decoder.JSONDecodeError:
                    continue

            print(f"Recuperati {len(events)} eventi da analizzare")
            # print(events)
            return events
        except Exception as e:
            print(f"Errore di lettura log: {e}")
            return []

    def close_conn(self):
        self.ssh_client.close()
        print("Connessione ad SSH chiusa")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Sistema di protezione ed analisi comportamentale')

    parser.add_argument('--host', help='Indirizzo IP di OPNsense (default: 192.168.1.250)', default='192.168.1.250')
    parser.add_argument('--port', type=int, help='Porta SSH (default: 22)', default=22)
    parser.add_argument('--user', type=str, help='Username', default="root")
    parser.add_argument('--pwrd', type=str, help='Password', default="opnsense")
    parser.add_argument('--treeshold', type=int, help='Soglia di tempo alert (default: 5)', default=5)

    args = parser.parse_args()

    print(args.host, "\n", args.port, "\n", args.user, "\n", args.pwrd, "\n")

    protection_sys = ProtectionSystem(ssh_host=args.host, ssh_port=args.port, ssh_user=args.user, ssh_pass=args.pwrd)
    protection_sys.ALERT_THREESHOLD = args.treeshold

    if args.user is None or args.pwrd is None:
        print("Username o password non corretti.")
    else:
        protection_sys.connect_ssh()
        analyze_events(protection_sys.fetch_recent_events())
        protection_sys.close_conn()
