import json
import socket
import time
from collections import defaultdict, Counter
from datetime import datetime
import paramiko


class BehavioralBlocker:
    def __init__(self, ssh_host, ssh_port, ssh_user, ssh_pass, alrt_tsld, alrt_rfrs):
        self.ssh_client = None
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_user = ssh_user
        self.ssh_pass = ssh_pass

        # Datasets per behavioural analysis
        self.ip_alerts = defaultdict(list)
        self.ip_attack_types = defaultdict(Counter)
        self.blocked_ips = set()

        # Duplicazioni
        self.processed_events = set()
        self.last_event_time = None

        # Soglie
        self.TIME_WINDOW = 300  # 5 minuti
        self.ALERT_THREESHOLD = alrt_tsld  # nr. max di alert entro la time window
        self.ALERT_REFRESH = alrt_rfrs

        print("Behavioral Blocker avviato")
        print(f"Soglia di rilevamento: {self.ALERT_THREESHOLD},"
              f"alert in {self.TIME_WINDOW} secondi,"
              f"refresh rate: {self.ALERT_REFRESH}\n")

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
        """Restituisco una lista degli ultimi 200 eventi dal log,
        se vi sono errori di lettura restituisco la lista vuota"""
        try:
            if self.last_event_time:
                cmd = f'tail -n 500 /var/log/suricata/eve.json | grep -v "^$"'
            else:
                cmd = f'tail -n {lines} /var/log/suricata/eve.json'

            stdin, stdout, stderr = self.ssh_client.exec_command(cmd)

            events = []
            tot_events = 0
            for line in stdout:
                try:
                    event = json.loads(line.strip())

                    # Ignora eventi non alert
                    if event.get('event_type') != 'alert':
                        continue

                    event_id = self.create_event_id(event)
                    tot_events += 1

                    # Salta evento se già precedentemente processato
                    if event_id in self.processed_events:
                        continue

                    event_time = self.parse_timestamp(event)

                    # Salta vecchi eventi se presente il periodo dell'ultimo evento
                    if self.last_event_time and event_time <= self.last_event_time:
                        continue

                    # Se arrivo qui, significa che l'evento è nuovo
                    events.append(event)
                    self.processed_events.add(event_id)

                    # Aggiorno il periodo dell'ultimo evento
                    if self.last_event_time or event_time > self.last_event_time:
                        self.last_event_time = event_time

                except Exception:
                    continue

            print(f"[{datetime.now()}] --> Recuperati {len(events)} eventi nuovi"
                  f" da analizzare (eventi totali: {tot_events})")
            # print(events)
            return events

        except Exception as e:
            print(f"Errore di lettura log: {e}")
            return []

    def analyze_events(self, events):
        """Analizza gli eventi basandosi sui pattern di comportamento"""
        threats = []

        # Salta eventi malformati senza campo 'src_ip'
        for event in events:
            src_ip = event.get('src_ip')
            if not src_ip:
                continue

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
                elif any(word in signature for word in ['sql', 'injection', 'mysql', '3306']):
                    return 'sqlinjection'

            attack_type = get_attack_type(signature)
            print(attack_type)

        return threats

    # Monitora gli alerts, con periodici aggiornamenti
    def continuous_monitoring(self, connected):
        try:
            while True:
                if not connected:
                    print("Connessione SSH fallita! Riprovo tra 30 secondi...")
                    time.sleep(30)
                    continue

                events = self.fetch_recent_events()

                time.sleep(self.ALERT_REFRESH)

                # if events:
                #     threats = self.analyze_events(events)
                #
                # for threat in threats:
                #     if threat['risk_level'] == 'HIGH':
                #         self.block_ip(threat)
                #     else:
                #         print(f"Indirizzo {threat['ip']} sotto osservazione ({threat['alert_count']} alerts generati)")


        except KeyboardInterrupt:
            pass

    def block_ip(self, threat_addr):
        print(f"Bloccaggio di {threat_addr}")

    def close_conn(self):
        self.ssh_client.close()
        print(f"\nConnessione SSH a {self.ssh_host} chiusa")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Sistema di protezione ed analisi comportamentale')

    parser.add_argument('--host', help='OPNsense IP addr (default: 192.168.1.250)', default='192.168.1.250')
    parser.add_argument('--port', type=int, help='SSH port (default: 22)', default=22)
    parser.add_argument('--user', type=str, help='Username', default='root')
    parser.add_argument('--pwrd', type=str, help='Password', default='opnsense')
    parser.add_argument('--tsld', type=int, help='No. of alerts before triggering block (default: 5)', default=5)
    parser.add_argument('--rfrs', type=int, help='Refresh alerts rate time', default=10)

    args = parser.parse_args()

    print(args.host, "\n", args.port, "\n", args.user, "\n", args.pwrd, "\n")

    protection_sys = BehavioralBlocker(ssh_host=args.host, ssh_port=args.port, ssh_user=args.user,
                                       ssh_pass=args.pwrd, alrt_tsld=args.tsld, alrt_rfrs=args.rfrs)

    # print (protection_sys.ALERT_THREESHOLD)

    connected = protection_sys.connect_ssh()

    if connected:
        protection_sys.continuous_monitoring(connected)
        protection_sys.close_conn()
