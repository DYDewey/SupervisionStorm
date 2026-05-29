from stormshield.sns.sslclient import SSLClient

host = input("IP du firewall : ")
user = input("Utilisateur : ")
password = input("Mot de passe : ")

client = SSLClient(
    host=host,
    port=443,
    user=user,
    password=password,
    sslverifypeer=False,
    sslverifyhost=False
)
try:
    reponse = client.send_command("SYSTEM LICENCE DUMP")
    print("\n===== BLOC DE DONNEES =====")
    print(reponse.output)
    print("===========================\n")
except Exception as e:
    print("Erreur :", e)
finally:
    try:
        client.disconnect()
    except Exception:
        pass