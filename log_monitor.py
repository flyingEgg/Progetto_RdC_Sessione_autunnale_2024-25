import json

import paramiko

ssh_client = paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh_client .connect("192.168.1.250", 22, "root","opnsense") # L'indirizzo IP andrà cambiato poi

stdin, stdout, stderr = ssh_client.exec_command("tail -n 100 /var/log/suricata/eve.json")
# log_data = stdout.read().decode()
#
# print(log_data)
# decoded_log_data = json.loads(log_data)

for line in stdout:
    event = json.loads(line.strip())
    print(event)

ssh_client.close()

# ???
