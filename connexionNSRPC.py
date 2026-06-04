from stormshield.sns.sslclient import SSLClient

# --- Configuration ---
FIREWALL_IP = "IP_STORMSHIELD"
USER = "USERSTORMSHIELD"
PASSWORD = "MOTDEPASSEDUSTORMSHIELD"
PORT_ADMIN = 443

def fetch_sns_stats():
    client = SSLClient(host=FIREWALL_IP, user=USER, password=PASSWORD, port=PORT_ADMIN, sslverifypeer=False)
    try:
        # Connexion au boîtier
        client.connect()
        print(f"\n Connexion reussi")
    except Exception as e:
        print(f"\n[!] Erreur de connexion ou d'exécution : {e}")
    
    finally:
        client.disconnect()

if __name__ == "__main__":
    fetch_sns_stats()