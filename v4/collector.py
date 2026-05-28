from stormshield.sns.sslclient import SSLClient
from datetime import datetime
import re

PORT_ADMIN = 443
VERIFY_SSL = False


def connexion_firewall(host, user, password, port=PORT_ADMIN):
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
        return client.send_command(commande)
    except Exception:
        return None


def extraire_avec_regex(texte, motif, valeur_par_defaut):
    match = re.search(motif, texte)
    if match:
        return match.group(1)
    return valeur_par_defaut


def recuperer_version_et_modele(client):
    reponse = envoyer_commande(client, "SYSTEM PROPERTY")
    version = "Inconnue"
    modele = "Inconnu"

    if reponse:
        if hasattr(reponse, "data") and "Result" in reponse.data:
            version = reponse.data["Result"].get("Version", "Inconnue")
            modele = reponse.data["Result"].get("Model", "Inconnu")
        elif hasattr(reponse, "output"):
            sortie = reponse.output
            version = extraire_avec_regex(sortie, r'Version=\"?([^\"\n]+)\"?', "Inconnue")
            modele = extraire_avec_regex(sortie, r'Model=\"?([^\"\n]+)\"?', "Inconnu")

    return version, modele


def recuperer_systeme(client):
    reponse = envoyer_commande(client, "MONITOR SYSTEM")
    sortie = reponse.output if reponse and hasattr(reponse, "output") else ""

    return {
        "uptime": extraire_avec_regex(sortie, r'uptime=([^,\s]+)', "Inconnu"),
        "cpu": extraire_avec_regex(sortie, r'CPU=([^,\s]+)', "Inconnu"),
        "ram": extraire_avec_regex(sortie, r'usermem=([^,\s]+)', "Inconnue"),
        "temperature": extraire_avec_regex(sortie, r'temperature=([^,\s]+)', "Inconnue")
    }


def recuperer_ha(client):
    reponse_config = envoyer_commande(client, "CONFIG HA SHOW")
    reponse_info = envoyer_commande(client, "HA INFO")
    reponse_mode = envoyer_commande(client, "hamode")

    sortie_config = reponse_config.output if reponse_config and hasattr(reponse_config, "output") else ""
    sortie_info = reponse_info.output if reponse_info and hasattr(reponse_info, "output") else ""
    sortie_mode = reponse_mode.output if reponse_mode and hasattr(reponse_mode, "output") else ""

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
    reponse = envoyer_commande(client, "MONITOR INTERFACE")
    sortie = reponse.output if reponse and hasattr(reponse, "output") else ""
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
    reponse = envoyer_commande(client, "SYSTEM LICENCE DUMP")
    sortie = reponse.output if reponse and hasattr(reponse, "output") else ""

    licence = {
        "statut": "Non trouvée",
        "version": "Inconnue",
        "expiration": "Inconnue"
    }

    if not sortie:
        return licence

    licence["statut"] = "Active"
    licence["version"] = extraire_avec_regex(sortie, r'Version[=:]\"?([^\n\"]+)\"?', "Inconnue")
    licence["expiration"] = extraire_avec_regex(sortie, r'NotAfter[=:]\"?([^\n\"]+)\"?', "Inconnue")

    return licence


def generer_resume_final(modele, version, ha, licence, interfaces):
    return f"{modele} | version {version} | {ha} | licence {licence['statut']} | {len(interfaces)} interfaces"


def construire_donnees_json(host, modele, version, systeme, ha, interfaces, licence):
    return {
        "date_audit": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host": host,
        "modele": modele,
        "version_firmware": version,
        "ha": ha,
        "systeme": systeme,
        "licence": licence,
        "interfaces": interfaces,
        "resume_final": generer_resume_final(modele, version, ha, licence, interfaces)
    }


def collecter_firewall(host, user, password, port=443):
    client = None

    try:
        client = connexion_firewall(host, user, password, port)

        version, modele = recuperer_version_et_modele(client)
        systeme = recuperer_systeme(client)
        ha = recuperer_ha(client)
        interfaces = recuperer_interfaces(client)
        licence = recuperer_licence(client)

        donnees = construire_donnees_json(
            host, modele, version, systeme, ha, interfaces, licence
        )
        donnees["statut"] = "OK"
        return donnees

    except Exception as e:
        return {
            "host": host,
            "statut": "KO",
            "erreur": str(e)
        }

    finally:
        if client:
            try:
                client.disconnect()
            except Exception:
                pass