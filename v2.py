from stormshield.sns.sslclient import SSLClient

# --- Configuration ---
FIREWALL_IP = "IP_STORMSHIELD"
USER = "USERSTORMSHIELD"
PASSWORD = "MOTDEPASSEDUSTORMSHIELD"
PORT_ADMIN = 4433


def fetch_sns_stats():
    client = SSLClient(host=FIREWALL_IP, user=USER, password=PASSWORD, port=PORT_ADMIN, sslverifypeer=False)

    try:
        client.connect()

        # --- RÉCUPÉRATION DES DONNÉES ---
        sys_info = client.send_command("MONITOR SYSTEM").output
        iface_info = client.send_command("MONITOR INTERFACE").output
        version_info = client.send_command("MONITOR VERSION").output
        license_info = client.send_command("MONITOR LICENSE").output
        
        # Le HA peut échouer si non configuré, on sécurise
        try:
            ha_info = client.send_command("MONITOR HA").output
        except:
            ha_info = "HA=Disabled"

        print("="*65)
        print(f" AUDIT COMPLET STORMSHIELD : {FIREWALL_IP} ")
        print("="*65)

        # 1. VERSION & FIRMWARE
        version = "Inconnue"
        for line in version_info.splitlines():
            if "version=" in line: version = line.split('=')[1]
        print(f"\n[FIRMWARE] Version SNS : {version}")

        # 2. ÉTAT DU CLUSTER (HA)
        ha_status = "Seul (Standalone)"
        if "state=active" in ha_info.lower(): ha_status = "Cluster ACTIVE"
        elif "state=backup" in ha_info.lower(): ha_status = "Cluster BACKUP (Passif)"
        print(f"[HA/CLUSTER] État : {ha_status}")

        # 3. SYSTÈME & RESSOURCES
        print("\n--- [ RESSOURCES ] ---")
        for line in sys_info.splitlines():
            line = line.strip()
            if "CPU=" in line:
                val = line.split('=')[1].split(',')[0]
                print(f"  > CPU : {val}%")
            if "usermem=" in line:
                print(f"  > RAM : {line.split('=')[1]}%")
            if "temperature=" in line:
                print(f"  > Température : {line.split('=')[1]}°C")

        # 4. LICENCES & EXPIRATION
        print("\n--- [ LICENCES & MAINTENANCE ] ---")
        for line in license_info.splitlines():
            if "contract=" in line:
                # On extrait le nom du contrat et la date
                parts = {item.split('=')[0]: item.split('=')[1] for item in line.split() if '=' in item}
                nom = parts.get('contract', 'Inconnu')
                date_exp = parts.get('end', 'N/A')
                # On affiche seulement si c'est la maintenance principale ou les options majeures
                if nom in ["maintenance", "as", "av", "url"]:
                    print(f"  > {nom.upper():<12} : Expire le {date_exp}")

        # 5. RÉSEAU & WAN
        print("\n--- [ RÉSEAU & INTERFACES ] ---")
        for line in iface_info.splitlines():
            if "type=Ethernet" in line:
                p = {item.split('=')[0]: item.split('=')[1] for item in line.split() if '=' in item}
                name = p.get('name', '???').split(',')[0]
                addr = p.get('addr', 'No IP')
                link = "LINK OK" if p.get('plugged') == "1" else "NO LINK"
                
                # On identifie le WAN (souvent nommé 'out' ou Ethernet0)
                wan_tag = "[WAN] " if name.lower() == "out" or "Ethernet0" in line else "      "
                print(f"  {wan_tag} {name.upper():<10} | {addr:<18} | {link}")

        print("\n" + "="*65)

    except Exception as e:
        print(f"\n[!] ERREUR : {e}")
    finally:
        client.disconnect()

if __name__ == "__main__":
    fetch_sns_stats()