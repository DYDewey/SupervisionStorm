from stormshield.sns.sslclient import SSLClient

FIREWALL_IP = "FIREWALLIP"
USER = "USER"
PASSWORD = "PASSWORD"
PORT_ADMIN = "PORT"


def fetch_sns_stats():
    client = SSLClient(host=FIREWALL_IP, user=USER, password=PASSWORD, port=443, sslverifypeer=False)
    try:
        client.connect()
        system_info_resp = client.send_command("MONITOR SYSTEM")
        system_info = system_info_resp.output
        interfaces_resp = client.send_command("MONITOR INTERFACE")
        interfaces = interfaces_resp.output
        print("--- État du Stormshield ---")
        print(system_info)
        print("\n--- État des Interfaces ---")
        print(interfaces)

    except Exception as e:
        print(f"Erreur de connexion ou d'exécution : {e}")
    
    finally:
        client.disconnect()

if __name__ == "__main__":
    fetch_sns_stats()