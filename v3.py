from stormshield.sns.sslclient import SSLClient
from datetime import datetime
import getpass
import requests
import re
import sys

PORT_ADMIN = 443
VERIFY_SSL = False


def connexion_firewall(host, user, password, port):
    return SSLClient(
        host=host,
        port=port,
        user=user,
        password=password,
        sslverifypeer=VERIFY_SSL,
        sslverifyhost=False
    )


def envoyer_commande(client, commande):
    try:
        reponse = client.send_command(commande)
        if reponse and hasattr(reponse, "output"):
            return reponse.output
    except Exception:
        pass
    return ""


def extraire_avec_regex(texte, motif, valeur_par_defaut):
    match = re.search(motif, texte)
    if match:
        return match.group(1)
    return valeur_par_defaut


def recuperer_version(client):
    sortie = envoyer_commande(client, "SYSTEM PROPERTY")
    return extraire_avec_regex(sortie, r'Version="?([^"\n]+)"?', "Inconnue")


def recuperer_systeme(client):
    sortie = envoyer_commande(client, "MONITOR SYSTEM")

    return {
        "uptime": extraire_avec_regex(sortie, r'uptime=([^,\s]+)', "Inconnu"),
        "cpu": extraire_avec_regex(sortie, r'CPU=([^,\s]+)', "Inconnu"),
        "ram": extraire_avec_regex(sortie, r'usermem=([^,\s]+)', "Inconnue"),
        "temperature": extraire_avec_regex(sortie, r'temperature=([^,\s]+)', "Inconnue")
    }


def recuperer_ha(client):
    sortie_config = envoyer_commande(client, "CONFIG HA SHOW")
    sortie_info = envoyer_commande(client, "HA INFO")
    sortie_mode = envoyer_commande(client, "hamode")

    if "State=0" in sortie_config:
        return "HA non activé"
    elif "State=1" in sortie_config:
        if "Mode=Active" in sortie_info or "HA Mode : Active" in sortie_mode:
            return "HA activé - noeud actif"
        elif "Mode=Passive" in sortie_info or "HA Mode : Passive" in sortie_mode:
            return "HA activé - noeud passif"
        else:
            return "HA activé - état inconnu"
    return "Information HA non disponible"


def recuperer_interfaces(client):
    sortie = envoyer_commande(client, "MONITOR INTERFACE")
    interfaces = []

    for ligne in sortie.splitlines():
        if "type=Ethernet" in ligne:
            nom = extraire_avec_regex(ligne, r'name=([^,\s]+)', "Inconnu")
            ip = extraire_avec_regex(ligne, r'addr=([^,\s]+)', "Pas d'IP")
            etat = "UP" if "plugged=1" in ligne else "DOWN"

            interfaces.append({
                "nom": nom,
                "ip": ip,
                "etat": etat
            })

    return interfaces


def recuperer_licence(client):
    sortie = envoyer_commande(client, "SYSTEM LICENCE DUMP")
    licence = {
        "statut": "Non trouvée",
        "version": "Inconnue",
        "expiration": "Inconnue"
    }

    if not sortie:
        return licence

    licence["statut"] = "Active"
    licence["version"] = extraire_avec_regex(sortie, r'Version[=:]"?([^\n"]+)"?', "Inconnue")
    licence["expiration"] = extraire_avec_regex(sortie, r'NotAfter[=:]"?([^\n"]+)"?', "Inconnue")

    try:
        date_exp = datetime.strptime(licence["expiration"], "%Y-%m-%d")
        if date_exp.date() < datetime.today().date():
            licence["statut"] = "Expirée"
    except ValueError:
        pass

    return licence


def afficher_resultats(host, version, systeme, ha, interfaces, licence):
    print("\n" + "=" * 60)
    print(f"AUDIT DU FIREWALL : {host}")
    print("=" * 60)

    print(f"\nVersion firmware : {version}")
    print(f"Etat HA          : {ha}")

    print("\n--- RESSOURCES SYSTEME ---")
    print(f"Uptime       : {systeme['uptime']}")
    print(f"CPU          : {systeme['cpu']} %")
    print(f"RAM          : {systeme['ram']} %")
    print(f"Température  : {systeme['temperature']} °C")

    print("\n--- LICENCE ---")
    print(f"Statut       : {licence['statut']}")
    print(f"Version      : {licence['version']}")
    print(f"Expiration   : {licence['expiration']}")

    print("\n--- INTERFACES ---")
    if interfaces:
        for interface in interfaces:
            print(f"{interface['nom']} - {interface['ip']} - {interface['etat']}")
    else:
        print("Aucune interface trouvée")

    print("=" * 60)


def main():
    print("--- CONNEXION STORMSHIELD ---")

    host = input("IP du firewall : ").strip()
    user = input("Utilisateur : ").strip()
    password = getpass.getpass("Mot de passe : ")

    port_texte = input("Port (443 par défaut) : ").strip()
    port = PORT_ADMIN if port_texte == "" else int(port_texte)

    client = None

    try:
        print(f"\n[*] Connexion à {host}:{port}...")
        client = connexion_firewall(host, user, password, port)
        print("[+] Connexion réussie")

        version = recuperer_version(client)
        systeme = recuperer_systeme(client)
        ha = recuperer_ha(client)
        interfaces = recuperer_interfaces(client)
        licence = recuperer_licence(client)

        afficher_resultats(host, version, systeme, ha, interfaces, licence)

    except ValueError:
        print("\n[ERREUR] Le port doit être un nombre.")
        sys.exit(1)
    except requests.exceptions.ConnectTimeout:
        print("\n[ERREUR] Connexion impossible.")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print("\n[ERREUR] Firewall injoignable.")
        sys.exit(1)
    except requests.exceptions.SSLError:
        print("\n[ERREUR] Problème SSL.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[INFO] Programme interrompu.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERREUR] Une erreur est survenue : {e}")
        sys.exit(1)
    finally:
        if client:
            try:
                client.disconnect()
            except Exception:
                pass


if __name__ == "__main__":
    main()