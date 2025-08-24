# Semplice classe di filtraggio per eventi non malevoli ma che possono generare alerts
class EventFilter:
    def __init__(self, ip_addr):
        # Signatures di suricata da ignorare
        self.BENIGN_SIGNATURES = {
            "ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management",
            "ET POLICY Outbound Debian APT User-Agent",
            "ET POLICY Ubuntu APT User-Agent"
        }

        self.WHITELIST_IPS = {ip_addr}

    def is_benign(self, event):
        """Restituisce True se l'evento va ignorato"""
        src_ip = event.get('src_ip', '')
        signature = event.get('alert', {}).get('signature', '')

        if src_ip in self.WHITELIST_IPS:
            return True

        if signature in self.BENIGN_SIGNATURES:
            return True

        return False
