import json
import socket
import time
from collections import defaultdict, Counter
from datetime import datetime, timezone
import paramiko
from EventFilter import EventFilter


class BehavioralBlocker:
    def __init__(self, ssh_host, ssh_port, ssh_user, ssh_pass, alrt_tsld, alrt_wdow, alrt_rfsh, ):
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
        self.TIME_WINDOW = alrt_wdow        # finestra di tempo alerts
        self.ALERT_THREESHOLD = alrt_tsld   # nr. max di alert entro la time window
        self.ALERT_REFRESH = alrt_rfsh      # frequenza di aggiornamento dal log

        self.event_filter = EventFilter(self.ssh_host)

        self.tot_events = 0

        print("Behavioral Blocker avviato\n")
        print(f"Indirizzi bloccati se generano {self.ALERT_THREESHOLD} alerts in {self.TIME_WINDOW} secondi")
        print(f"refresh rate: {self.ALERT_REFRESH} secondi\n")

    def connect_ssh(self):
        """Stabilisco una connessione SSH ad OPNsense e gestisco eventuali errori di connessione"""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(self.ssh_host, self.ssh_port, self.ssh_user, self.ssh_pass, timeout=10)
            print(f"Connesso ad OPNsense ({self.ssh_host}) via SSH")
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

            for line in stdout:
                try:
                    event = json.loads(line.strip())

                    # Ignora eventi non alert
                    if event.get('event_type') != 'alert':
                        continue

                    event_id = self.create_event_id(event)

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
                    self.tot_events += 1

                    # Aggiorno il periodo dell'ultimo evento
                    if self.last_event_time or event_time > self.last_event_time:
                        self.last_event_time = event_time

                except Exception:
                    continue

            print(f"[{datetime.now()}] --> Recuperati {len(events)} eventi nuovi"
                  f" da analizzare (eventi totali: {self.tot_events})")
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

            # Salta eventi non malevoli (es apt update del server)
            if self.event_filter.is_benign(event):
                continue

            # Parsing del timestamp con conversione in oggetto datetime
            event_time = self.parse_timestamp(event)

            # Analisi del tipo di attacco
            alert_info = event.get('alert', {})
            signature = alert_info.get('signature', '').lower()

            # Classifico il tipo di attacco
            def get_attack_type(signature):
                if any(word in signature for word in ['nmap', 'NMAP', 'reconnaissance', 'port scan', 'PORT SCAN']):
                    return 'portscan'
                elif any(word in signature for word in ['brute', 'force', 'login', 'ssh', 'frequent']):
                    return 'bruteforce'
                elif any(word in signature for word in ['exploit', 'attack', 'payload']):
                    return 'exploit'
                elif any(word in signature for word in ['sql', 'SQL', 'injection', 'SQLi', '3306', 'UNION', 'SELECT']):
                    return 'sqlinjection'
                elif any (word in signature for word in ['flood', 'heavy', 'DOS', 'DoS', 'DDoS']):
                    return 'dos'
                else:
                    return 'unknown'

            attack_type = get_attack_type(signature)

            # Salvo l'alert
            self.ip_alerts[src_ip].append(event_time)
            self.ip_attack_types[src_ip][attack_type] +=1

        for ip in self.ip_alerts:
            if ip in self.blocked_ips:
                continue

            recent_alerts = [
                t for t in self.ip_alerts[ip]
                if (datetime.now(timezone.utc) - t).total_seconds() <= self.TIME_WINDOW
            ]

            # Se il numero di alerts di un IP supera la soglia impostata, scatta la blacklist di esso
            if len(recent_alerts) >= self.ALERT_THREESHOLD:
                threat={
                    "ip": ip,
                    "alert_count": len(recent_alerts),
                    "attack_types": dict(self.ip_attack_types[ip]),
                    "threat_level": 'ALTO' if len(recent_alerts) > (self.ALERT_THREESHOLD * 2) else 'MEDIO'
                }
                threats.append(threat)

        return threats

    def show_stats(self):
        """Statistiche attuali"""
        print(f"\nSTATISTICHE ATTUALI [{datetime.now().strftime('%H:%M:%S')}]")
        print(f"Nr. di IP monitorati: {len(self.ip_alerts)}")
        print(f"IP bloccati: {len(self.blocked_ips)}")

        if self.blocked_ips:
            print(f"Bloccato: {', '.join(list(self.blocked_ips)[:5])}")

        # Mostra gli indirizzi più sospetti
        active_ips = []
        current_time = datetime.now().replace(tzinfo=datetime.now().astimezone().tzinfo)

        for ip, alerts in self.ip_alerts.items():
            recent_count = 0
            for alert_time in alerts:
                try:
                    # Assicura compatibilità fascia oraria
                    if alert_time.tzinfo is None:
                        alert_time = alert_time.replace(tzinfo=current_time.tzinfo)

                    if (current_time - alert_time).total_seconds() <= self.TIME_WINDOW:
                        recent_count += 1
                except TypeError:
                    continue

            if recent_count > 0:
                active_ips.append((ip, recent_count))

        if active_ips:
            active_ips.sort(key=lambda x: x[1], reverse=True)
            print("Indirizzi più attivi:")
            for ip, count in active_ips[:3]:
                print(f"   {ip}: {count} alerts recenti")

        print("-" * 50)

    def continuous_monitoring(self, connected):
        """Monitora gli alerts, con periodici aggiornamenti sino interruzione dell'utente"""
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
                        if threat['threat_level'] == 'ALTO':
                            self.block_ip(threat)
                        else:
                            print(f"Indirizzo {threat['ip']} sotto osservazione ({threat['alert_count']} alerts generati)")

                # self.show_stats()
                time.sleep(self.ALERT_REFRESH)
        except KeyboardInterrupt:
            self.close_conn()
            pass

    def block_ip(self, threat_info):
        """Bloccaggio di ip minaccioso mediante creazione apposita regola di firewall"""
        ip = threat_info['ip']

        print("\nMINACCIA RILEVATA")
        print(f"Ip: {threat_info['ip']}")
        print(f"Nr. di alerts: {threat_info['alert_count']}")
        print(f"Classe di attacchi: {threat_info['attack_types']}")
        print(f"Livello di minaccia: {threat_info['threat_level']}")

        # Bloccaggio dell'ip
        try:
            import requests
            import json
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

            host = self.ssh_host
            api_key = "ZUAoK6FdsctPNn/r+nG2rmp9Au19zzrYOZ/SWY6QVwO27041pZfhiWWP1+pARZiVLYlw48gszPQaB6tI"
            api_secret = "6Hcr/30aAqMhi5GlzumuYh+x7y6WmAsO7ByvbL6SAee1A8HWoaD6FeHg2bXOhvVVskxuRFOAJQtYiirY"
            url = f"https://{host}/api/firewall/filter/add_rule"

            # Payload con i dati della regola
            payload = {
                "rule": {
                    "enabled": "1",
                    "action": "block",
                    "quick": "1",
                    "interface": "opt1",
                    "direction": "in",
                    "protocol": "any",
                    "source": ip,
                    "source_net": ip,
                    "destination": "any",
                    "description": f"BLOCCO a causa di: {threat_info['attack_types']} -- alerts causati: {threat_info['alert_count']}",
                    "log": "1",
                }
            }

            # Chiamata API
            response = requests.post(
                url,
                auth=(api_key, api_secret),
                json=payload,
                verify=False,
                timeout=10
            )

            if response.status_code == 200:
                result = response.json()
                if result.get("result") == "saved":
                    print(f"Regola firewall creata per bloccare {ip}")

                    # Applica le modifiche
                    apply_url = f"https://{host}/api/firewall/filter/apply"
                    apply_response = requests.post(apply_url, auth=(api_key, api_secret), verify=False)

                    if apply_response.status_code == 200:
                        print("Configurazione applicata")
                    else:
                        print("Configurazione non applicata")
                else:
                    print(f"Errore: {result}")
            else:
                print(f"Errore HTTP: {response.status_code} - {response.text}")

        except Exception as e:
            print(f"Errore: {e}")

        self.blocked_ips.add(ip)

        with open('blocked_ips.log', 'a') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] {ip} - {threat_info['alert_count']} alerts\n")

        return True

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
    parser.add_argument('--tsld', type=int, help='Soglia di alerts prima di innescare blacklist (default: 5)', default=5)
    parser.add_argument('--wdow', type=int, help='Finestra di tempo entro quale superare la soglia (default: 300 s)', default=300)
    parser.add_argument('--rfsh', type=int, help='Refresh rate lettura log', default=10)

    args = parser.parse_args()

    print("Host: ", args.host, "\nPorta: ", args.port, "\nUtente: ", args.user, "\n")

    protection_sys = BehavioralBlocker(ssh_host=args.host, ssh_port=args.port, ssh_user=args.user,
                                       ssh_pass=args.pwrd, alrt_tsld=args.tsld, alrt_wdow=args.wdow,
                                       alrt_rfsh=args.rfsh)

    connected = protection_sys.connect_ssh()

    if connected:
        protection_sys.continuous_monitoring(connected)
