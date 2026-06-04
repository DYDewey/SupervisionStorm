from stormshield.sns.sslclient import SSLClient

# --- Configuration ---
FIREWALL_IP = "192.168.1.1"
USER = "admin"
PASSWORD = "G2j@x5f2XK7e!HM4y3"
PORT_ADMIN = "443"


def fetch_sns_stats():
    # Correction des arguments : sslverifypeer pour ignorer le certificat auto-signé
    client = SSLClient(host=FIREWALL_IP, user=USER, password=PASSWORD, port=PORT_ADMIN, sslverifypeer=False)

    try:
        # Connexion au boîtier
        client.connect()
        # 1. Récupération des infos système (CPU, RAM, Temp, Uptime)
        # On utilise MONITOR au lieu de CONFIG MONITOR (qui est pour la config)
        system_info_resp = client.send_command("MONITOR SYSTEM")
        system_info = system_info_resp.output
        # 2. Récupération de l'état des interfaces
        interfaces_resp = client.send_command("MONITOR INTERFACE")
        interfaces = interfaces_resp.output
        print("="*50)
        print(f" SUPERVISION STORMSHIELD : {FIREWALL_IP} ")
        print("="*50)

        print("\n--- [ ÉTAT SYSTÈME ] ---")
        for line in system_info.splitlines():
            line = line.strip()
            if "uptime=" in line:
                print(f"  > Uptime      : {line.split('=')[1]}")
            if "CPU=" in line:
                # On prend la première valeur du CPU
                cpu_val = line.split('=')[1].split(',')[0]
                print(f"  > Charge CPU  : {cpu_val}%")
            if "usermem=" in line:
                print(f"  > Utilisation RAM : {line.split('=')[1]}%")
            if "temperature=" in line:
                print(f"  > Température : {line.split('=')[1]}°C")

        print("\n--- [ ÉTAT DES INTERFACES PHYSIQUES ] ---")
        for line in interfaces.splitlines():
            # On filtre pour n'afficher que les vraies cartes Ethernet (on vire les tunnels)
            if "type=Ethernet" in line:
                # Extraction des infos par découpage
                parts = {item.split('=')[0]: item.split('=')[1] for item in line.split() if '=' in item}
                
                name = parts.get('name', 'Inconnu').split(',')[0] 
                addr = parts.get('addr', 'Pas d\'IP')
                status = "UP (Connecté)" if parts.get('plugged') == "1" else "DOWN (Déconnecté)"
                
                print(f"  > {name.upper():<10} | IP: {addr:<18} | Statut: {status}")

    except Exception as e:
        print(f"\n[!] Erreur de connexion ou d'exécution : {e}")
    
    finally:
        # Très important : on libère le slot d'administration
        client.disconnect()

if __name__ == "__main__":
    fetch_sns_stats()