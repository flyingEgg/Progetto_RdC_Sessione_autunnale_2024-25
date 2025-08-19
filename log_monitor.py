import json
from collections import defaultdict, Counter

import paramiko


class SuricataAnalyzer:
    def __init__(self, ssh_host="192.168.1.250", ssh_port=22, ssh_user="root", ssh_pass="opnsense"):
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_pass = ssh_pass

        # Datasets per behavioural analysis
        self.ip_alerts = defaultdict(list)
        self.ip_attack_types = defaultdict(Counter)

        self.TIME_WINDOW      = 300         # 5 minuti
        self.ALERT_THREESHOLD = 10          # nr. max di alert entro la time window
        self.SUSPICIOUS_KEYWORDS =  [
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

    def fetch_logs(self):
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

    def analyze_events(self, event):

    def close_conn(self):
        self.ssh_client.close()
        print("Connessione SSH chiusa")




if __name__ == "__main__":
    analyzer = SuricataAnalyzer()
    analyzer.connect_ssh()
    analyzer.fetch_logs()
    analyzer.close_conn()
