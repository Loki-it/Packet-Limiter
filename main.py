import subprocess
import collections
import os
import re

# Limite di pacchetti
LIMIT = 1000

# Interfaccia di rete
INTERFACE = 'eth0'

# Usa un defaultdict per contare i pacchetti per ogni IP
ip_counts = collections.defaultdict(int)

# Usa un set per tenere traccia degli IP bloccati
blocked_ips = set()

# Ottieni l'indirizzo IP dell'utente connesso via SSH
ssh_client_ip = None
if 'SSH_CLIENT' in os.environ:
    ssh_client_ip = os.environ['SSH_CLIENT'].split(' ')[0]

# Pattern per trovare un indirizzo IP in una stringa
ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def extract_attacker_ip(row):
    # Trova tutti gli indirizzi IP nella stringa
    ips = ip_pattern.findall(row)
    
    if not ips:
        return None
    
    # L'indirizzo IP dell'attaccante è il primo indirizzo IP trovato nella stringa
    return ips[0]

try:
    # Esegui tcpdump e cattura i pacchetti in arrivo
    with subprocess.Popen(['tcpdump', '-n', '-l', '-i', INTERFACE, 'ip'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True) as process:
        for row in iter(process.stdout.readline, ''):
            # Estrai l'indirizzo IP dell'attaccante dal output di tcpdump
            attacker_ip = extract_attacker_ip(row)
            
            if not attacker_ip:
                print(f"Impossibile estrarre l'IP da: {row.strip()}")
                continue
            
            # Salta l'IP dell'utente SSH
            if attacker_ip == ssh_client_ip:
                continue
                
            ip_counts[attacker_ip] += 1
            
            # Se l'IP ha superato il limite e non è ancora stato bloccato
            if ip_counts[attacker_ip] > LIMIT and attacker_ip not in blocked_ips:
                # Blocca l'IP specifico con iptables
                subprocess.run(['iptables', '-A', 'INPUT', '-s', attacker_ip, '-j', 'DROP'])
                print(f"IP {attacker_ip} bloccato.")
                
                # Aggiungi l'IP all'insieme degli IP bloccati
                blocked_ips.add(attacker_ip)
except KeyboardInterrupt:
    print("Interrotto dall'utente.")
finally:
    process.terminate()
