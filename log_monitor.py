import json
from sys import stdin, stdout, stderr

import paramiko

ssh_client = paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh_client .connect("192.168.1.250", 22, "root","opnsense") # L'indirizzo IP andrà cambiato poi

stdin, stdout, stderr = ssh_client.exec_command("cat /var/log/suricata/eve.json")
log_data = stdout.read().decode()

print(log_data[:500])
# decoded_log_data = json.loads(log_data)

ssh_client.close()

# ???
