# 🔐 ARP Spoofer & arpSafe

**ARP Spoofer** is a tool for conducting ARP poisoning (MITM/disassociation) attacks on a local network, while **arpSafe** is its defensive counterpart, providing live detection and prevention against such threats.

---

## 📌 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Demo](#demo)
- [Installation](#installation)
- [Usage](#usage)
  - [arpSpoofer](#arpspoofer)
  - [arpSafe](#arpsafe)
- [Dependencies](#dependencies)
- [Security & Ethical Use](#security--ethical-use)
- [License](#license)

---

## ⚙️ Overview

This dual-toolset project demonstrates:
- Active ARP Spoofing via forged ARP replies.
- Optional disassociation mode using random MACs.
- IP forwarding and MITM handling.
- Real-time ARP spoofing detection and dynamic mitigation.
- `arptables` integration for automatic attacker blocking.

---

## ✨ Features

| Feature | arpSpoofer | arpSafe |
|--------|-------------|----------|
| ARP Poisoning | ✅ | 🚫 |
| Disassociation (random MAC) | ✅ | 🚫 |
| IP Forwarding Support | ✅ | 🚫 |
| Real-Time Logging | ✅ | ✅ |
| Dynamic Detection | 🚫 | ✅ |
| Automatic MAC Blocking | 🚫 | ✅ |
| Static ARP Binding | 🚫 | ✅ |
| arptables Integration | 🚫 | ✅ |
| Graceful Exit Handling | ✅ | ✅ |


---

## 🧪 Installation

```bash
git clone https://github.com/kirtana442/ARP_Spoofing_Detection_Prevention

```

Install system dependencies:

```bash
sudo apt install arptables
```

---

## 🚀 Usage
🔴 arpSpoofer: Active ARP Poisoning Tool

```bash
sudo python3 arp_spoofer.py -t <target_ip> [-s <gateway_ip>] [-i <interface>] [-ti <time_interval>] [-ipf] [-d]
```

Options:

-t, --target: Target IP (Required)

-s, --gateway: Gateway IP (optional; auto-detects if not given)

-i, --interface: Network interface (e.g., eth0, wlan0)

-ti, --time_interval: Time between packets (default: 10s)

-ipf, --ipforward: Enable IP forwarding

-d, --disassociate: Enable random MAC disassociation attack

📌 Logs saved in arp_spoofer_log.txt

---

## 🛡️ arpSafe: Real-time Detection and Defense Tool

```bash
sudo python3 arpSafe.py
```
What it does:

Monitors ARP traffic for spoofed packets

Blocks attacker MACs via arptables

Binds your router’s MAC as static to avoid poisoning

Logs all activity to arp_safe_log.txt

⛑️ Automatically restores system ARP and arptables state on exit (CTRL+C)


## 📦 Dependencies
Install via pip:

```bash
pip install scapy netifaces colorama
```

---

## System requirements:

Linux OS

arptables installed

Root privileges

---

## ⚠️ Security & Ethical Use
This project is strictly for educational 

Never use ARP spoofing tools on networks you don’t own or have explicit permission to test. 

