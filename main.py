import subprocess
import os
import re

TCP_LIMIT = 1000  # limite per pacchetti TCP
UDP_LIMIT = 10000  # limite per pacchetti UDP
INTERFACE = 'eth0'

tcp_ip_counts = {}
udp_ip_counts = {}
blocked_ips = set()

ssh_client_ip = os.environ.get('SSH_CLIENT', '').split(' ')[0] if 'SSH_CLIENT' in os.environ else None
ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def extract_attacker_ip(row):
    ips = ip_pattern.findall(row)
    return ips[0] if ips else None

try:
    with subprocess.Popen(['tcpdump', '-n', '-l', '-i', INTERFACE, 'ip', 'and', '(tcp or udp)'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True) as process:
        for row in iter(process.stdout.readline, ''):
            attacker_ip = extract_attacker_ip(row)
            
            if not attacker_ip or attacker_ip == ssh_client_ip:
                continue
            
            if 'TCP' in row:
                tcp_ip_counts[attacker_ip] = tcp_ip_counts.get(attacker_ip, 0) + 1
                limit_reached = tcp_ip_counts[attacker_ip] > TCP_LIMIT
            elif 'UDP' in row:
                udp_ip_counts[attacker_ip] = udp_ip_counts.get(attacker_ip, 0) + 1
                limit_reached = udp_ip_counts[attacker_ip] > UDP_LIMIT
            else:
                continue  # ignora altri tipi di pacchetti
            
            if limit_reached and attacker_ip not in blocked_ips:
                subprocess.run(['iptables', '-A', 'INPUT', '-s', attacker_ip, '-j', 'DROP'])
                blocked_ips.add(attacker_ip)
                print(f"IP {attacker_ip} bloccato.")
except KeyboardInterrupt:
    print("Interrotto dall'utente.")
finally:
    process.terminate()
