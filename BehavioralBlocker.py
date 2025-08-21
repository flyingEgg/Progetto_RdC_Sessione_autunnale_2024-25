import json
import socket
import time
from collections import defaultdict, Counter
from datetime import datetime

import paramiko


class BehavioralBlocker:
    def __init__(self, ssh_host, ssh_port, ssh_user, ssh_pass, treeshold):
        self.ssh_client = None
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_pass = ssh_pass

        # Datasets per behavioural analysis
        self.ip_alerts = defaultdict(list)
        self.ip_attack_types = defaultdict(Counter)

        self.TIME_WINDOW = 300  # 5 minuti
        self.ALERT_THREESHOLD = treeshold  # nr. max di alert entro la time window

        print("Behavioral Blocker avviato")
        print(f"Soglia: {self.ALERT_THREESHOLD}, alert in {self.TIME_WINDOW} secondi")


    # Stabilisco una connessione SSH ad OPNsense e gestisco errori nella connessione
    def connect_ssh(self):
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(self.ssh_host, self.ssh_port, self.ssh_user, self.ssh_pass, timeout=10)
            print("Connesso ad SSH")
            return True
        except paramiko.AuthenticationException:
            print("Errore di autenticazione SSH")
            return False
        except socket.timeout:
            print("Timeout: host irraggiungibile")
            return False
        except paramiko.SSHException as e:
            print(f"Errore SSH: {e}")
            return False
        except Exception as e:
            print(f"Errore generale di connessione ad SSH: {e}")
            return False

    def parse_timestamp(self, event):
        """Parsing del timestamp con conversione in oggetto datetime"""
        from dateutil import parser

        try:
            timestamp_str = event.get('timestamp', '')
            if timestamp_str:
                return parser.isoparse(timestamp_str)
            else:
                return datetime.now()
        except(ValueError, AttributeError):
            return datetime.now()

    def create_event_id(self, event):
        """Crea un id univoco basato su timestamp, ip e signature per evitare duplicati"""
        timestamp = event.get('timestamp', '')
        ip = event.get('src_ip', '')
        signature = event.get('alert', {}).get('signature', '')
        dest_port = event.get('dest_port', '')

        import hashlib
        unique_id = f"f{timestamp}_{ip}_{signature}_{dest_port}"
        return hashlib.md5(unique_id.encode()).hexdigest()

    def fetch_recent_events(self, lines=200):
        """Restituisco una lista degli ultimi 200 eventi dal log, se vi sono errori di lettura restituisco la lista vuota"""
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

    def analyze_events(self, events):
        threats = []

        # Salta eventi malformati senza campo 'src_ip'
        for event in events:
            src_ip = event.get('src_ip')
            if not src_ip:
                continue

                # ____________________________________________________________________ non so se ignorare ip domestici, ci penserò

            # Parsing del timestamp con conversione in oggetto datetime
            event_time = self.parse_timestamp(event)
            print(event_time)

            # Analisi del tipo di attacco
            alert_info = event.get('alert', {})
            signature = alert_info.get('signature', '').lower()


            # Classifico il tipo di attacco
            def get_attack_type(signature):
                if any(word in signature for word in ['scan', 'reconnaissance', 'nmap', 'port']):
                    return 'portscan'
                elif any(word in signature for word in ['brute', 'force', 'login']):
                    return 'bruteforce'
                elif any(word in signature for word in ['exploit', 'attack', 'payload']):
                    return 'exploit'
                return 'unknown'

            attack_type = get_attack_type(signature)
            print(attack_type)

        return threats

    def continuous_monitoring(self, connected):
        try:
            while True:
                if not connected:
                    print("Connessione SSH fallita! Riprovo tra 30 secondi...")
                    time.sleep(30)
                    continue

                events = self.fetch_recent_events()

                if events:
                    threats = self.analyze_events(events)

                for threat in threats:
                    if threat['risk_level'] == 'HIGH':
                        self.block_ip(threat)
                    else:
                        print(f"Indirizzo {threat['ip']} sotto osservazione ({threat['alert_count']} alerts generati)")


        except KeyboardInterrupt:
            pass

    def block_ip(self, threat_addr):
        print(f"Bloccaggio di {threat_addr}")

    def close_conn(self):
        self.ssh_client.close()
        print("Connessione ad SSH chiusa")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Sistema di protezione ed analisi comportamentale')

    parser.add_argument('--host', help='Indirizzo IP di OPNsense (default: 192.168.1.250)', default='192.168.1.250')
    parser.add_argument('--port', type=int, help='Porta SSH (default: 22)', default=22)
    parser.add_argument('--user', type=str, help='Username', default='root')
    parser.add_argument('--pwrd', type=str, help='Password', default='opnsense')
    parser.add_argument('--treeshold', type=int, help='Soglia di tempo alert (default: 5)', default=5)

    args = parser.parse_args()

    print(args.host, "\n", args.port, "\n", args.user, "\n", args.pwrd, "\n")

    protection_sys = BehavioralBlocker(ssh_host=args.host, ssh_port=args.port, ssh_user=args.user, ssh_pass=args.pwrd, treeshold=args.treeshold)
    protection_sys.ALERT_THREESHOLD = args.treeshold
    # print (protection_sys.ALERT_THREESHOLD)

    connected = protection_sys.connect_ssh()

    if connected:

        protection_sys.continuous_monitoring(connected)
        protection_sys.close_conn()
