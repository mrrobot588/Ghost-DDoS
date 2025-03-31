# Ghost-DDoS
![{AC350EA3-6547-46DC-8B84-E3C98596334D}](https://github.com/user-attachments/assets/d25bf06a-9d55-4a9d-9926-1da17601b704)

Ghost DDoS Tool is a high-performance network stress testing and security auditing tool designed for penetration testers, security researchers, and CTF (Capture The Flag) participants. It provides multiple attack vectors, proxy support, and botnet capabilities for advanced testing scenarios.

WARNING: This tool is intended for legal security research and authorized penetration testing only. Unauthorized use against systems you do not own is illegal.

Key Features
✔ Multi-Vector Attacks – HTTP Flood, Slowloris, RUDY, and mixed attack modes
✔ Proxy Support – Tor, public proxies, custom proxies, and hybrid rotation
✔ Stealth Mode – Evasion techniques to bypass basic detection
✔ CTF Mode – Pre-loaded payloads for web exploitation challenges
✔ Botnet Integration – Manage compromised nodes for distributed attacks
✔ Real-Time Stats – Monitor request rates, success rates, and active proxies
✔ GUI & CLI Options – User-friendly interface with logging

System Requirements
Python 3.8+ (Recommended: 3.10+)

OS: Windows (Best support), Linux (Experimental)

RAM: 2GB+ (4GB recommended for large-scale attacks)

Network: Stable internet connection (Proxy/Tor support required for anonymity)
Usage
Basic Attack
Enter the target URL (e.g., http://example.com)

Select attack type (HTTP Flood, Slowloris, etc.)

Choose proxy mode (Tor, Public, Hybrid)

Set thread count (100-10,000 recommended)

Click "Initiate Ghost Strike"

Botnet Commands
!scan – Scan for vulnerable nodes

!connect [IP] [PORT] [USER] [PASS] – Add a new bot

!ddos [TARGET] [THREADS] – Launch a distributed attack

!stop – Terminate all attacks

CTF Mode
Enable CTF Mode for pre-configured exploitation payloads:

SQLi (admin' OR 1=1--)

XSS (<script>alert(1)</script>)

Path Traversal (../../../etc/passwd)
