<img src="https://img.freepik.com/premium-vector/digital-eye-data-network-cyber-security-technology-vector-background-futuristic-tech-virtual-cyberspace-internet-secure-surveillance-binary-code-digital-eye-safety-scanner_8071-7138.jpg">

# PacketLimiter

![](https://img.shields.io/badge/Support-Linux-lightgrey) ![](https://img.shields.io/badge/Python->3.0-green)

Questo firewall è stato creato come alternativa alle regole iptables per bloccare attacchi Dos/DDos più leggeri in casi più specifici.
Lo script analizzerà in tempo reale ogni singolo ip e bloccherà gli ip che invieranno troppi pacchetti (puoi impostare te il numero di pacchetti).

---

### Prerequisiti 🔧

- Python 3+
- Screen
- Tcpdump

### Configurazione 🔧

- sudo apt-get install screen tcpdump 
- screen -S firewall python3 main.py

### Test Effettuati ✅
- Attacco da ip singolo: Bloccato 
- Attacco da una decina di ip: Bloccato
- Attacco da un centinaio di ip: Bloccato

### Avvertenze ⚠️

Lo script è stato creato per bloccare un numero limitato di ip, non è adatto per attacchi massivi.
Il dover bloccare un attacco massivo potrebbe rallentare molto l'host e lo stesso vale sull'avere migliaia di ip nelle iptables  

### Immagine dimostrativa

<img src="https://i.imgur.com/O06UlqN.jpg">

