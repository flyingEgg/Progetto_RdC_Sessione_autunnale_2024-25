import json
from collections import defaultdict, Counter

import paramiko


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

    def fetch_recent_events(self):
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(f"cat /var/log/suricata/eve.json")

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

    # stdin, stdout, stderr = ssh_client.exec_command("tail -n 100 /var/log/suricata/eve.json")
    # log_data = stdout.read().decode()
    #
    # print(log_data)
    # decoded_log_data = json.loads(log_data)

    # def analyze_events(self, event):

    def close_conn(self):
        self.ssh_client.close()
        print("Connessione ad SSH chiusa")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Sistema di protezione ed analisi comportamentale')

    parser.add_argument('--host', help='Indirizzo IP di OPNsense (default: 192.168.54.1)', default='192.168.54.1')
    parser.add_argument('--port', type=int, help='Porta SSH (default: 22)', default=22)
    parser.add_argument('--user', type=str, help='Username')
    parser.add_argument('--pwrd', type=str, help='Password')
    parser.add_argument('--treeshold', type=int, help='Soglia di tempo alert (default: 5)', default=5)

    args = parser.parse_args()

    print(args.host, "\n", args.port, "\n", args.user, "\n", args.pwrd, "\n")

    protection_sys = ProtectionSystem(ssh_host=args.host, ssh_port=args.port, ssh_user=args.user, ssh_pass=args.pwrd)
    protection_sys.ALERT_THREESHOLD = args.treeshold

    if args.user is None or args.pwrd is None:
        print("Username o password non corretti.")
    else:
        protection_sys.connect_ssh()
        protection_sys.fetch_recent_events()
        # protection_sys.analyze_events()
        protection_sys.close_conn()
