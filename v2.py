from stormshield.sns.sslclient import SSLClient

import getpass # Pour cacher le mot de passe quand on le tape
import re


def fetch_sns_stats():
    print("--- [ CONNEXION STORMSHIELD ] ---")
    
    # On demande les infos en direct
    host = input("IP du Firewall : ")
    user = input("Utilisateur (ex: admin) : ")
    
    # getpass évite que le mot de passe s'affiche en clair dans le terminal
    password = getpass.getpass("Mot de passe : ") 
    
    port_input = input("Port (par défaut 443) : ")
    port = int(port_input) if port_input else 443

    # On initialise le client avec les saisies
    client = SSLClient(host=host, user=user, password=password, port=port, sslverifypeer=False)

    try:
        print(f"\n[*] Tentative de connexion à {host}...")
        client.connect()
        print("[+] Connexion établie !\n")

        # --- RÉCUPÉRATION DES DONNÉES ---
        sys_info = client.send_command("MONITOR SYSTEM").output
        iface_info = client.send_command("MONITOR INTERFACE").output
        
        # Version
        version = "Inconnue"
        try:
            version_info = client.send_command("SYSTEM PROPERTY").output.strip()
            if "00100200" not in version_info:
                m = re.search(r'Version="?([^"\n]+)"?', version_info, re.IGNORECASE)
                if m:
                    version = m.group(1).strip()
        except:
            pass
        
        # Licences updater
        try:
            licence_updater = client.send_command("SYSTEM LICENCE UPDATER SHOW").output
        except:
            licence_updater = ""
        
        # HA
        try:
            ha_info = client.send_command("MONITOR HA").output
        except:
            ha_info = "HA=Disabled"

        print("="*65)
        print(f" AUDIT COMPLET STORMSHIELD : {host} ")
        print("="*65)

        print(f"\n[FIRMWARE] Version SNS : {version}")

        # HA
        ha_status = "Seul (Standalone)"
        if "state=active" in ha_info.lower():
            ha_status = "Cluster ACTIVE"
        elif "state=backup" in ha_info.lower():
            ha_status = "Cluster BACKUP (Passif)"
        print(f"[HA/CLUSTER] État : {ha_status}")

        # Ressources
        print("\n--- [ RESSOURCES ] ---")
        for line in sys_info.splitlines():
            line = line.strip()
            if "CPU=" in line:
                try:
                    val = line.split('=')[1].split(',')[0]
                    print(f"  > CPU : {val}%")
                except:
                    pass
            if "usermem=" in line:
                try:
                    print(f"  > RAM : {line.split('=')[1].split(',')[0]}%")
                except:
                    pass
            if "temperature=" in line:
                try:
                    print(f"  > Température : {line.split('=')[1].split(',')[0]}°C")
                except:
                    pass

        # Licences updater
        print("\n--- [ LICENCES & MAINTENANCE ] ---")
        if licence_updater and "00100200" not in licence_updater:
            print("  > Module updater : ACTIVÉ")
            try:
                last_check = re.search(r'LastCheck="([^"]+)"', licence_updater)
                if not last_check:
                    last_check = re.search(r'last="([^"]+)"', licence_updater, re.IGNORECASE)
                if last_check:
                    print(f"  > Dernière vérif : {last_check.group(1)}")
            except:
                pass
        else:
            print("  > Module updater : Non disponible")

        # LICENCES – on se concentre sur celles qui ont une Expdate
        licence_commands = [
            ("ANTIVIRUS ", "CONFIG ANTIVIRUS LICENCE"),
            ("URL      ", "CONFIG URL LICENCE"), 
            ("AS       ", "CONFIG AS LICENCE"),
            ("URLFILTER", "CONFIG URLFILTERING LICENCE"),
            # Ajout éventuel de packs spécifiques Stormshield type « Breach Fighter », etc.
            # ("PACK_XXX ", "CONFIG PACK XXX LICENCE"),
        ]
        
        print("\n  > Dates d'expiration des licences (si présentes) :")
        any_found = False
        for nom, cmd in licence_commands:
            try:
                output = client.send_command(cmd).output.strip()

                # On ne touche qu'aux lic. non génériques et non absentes
                if "00100200" not in output and "Pas assez" not in output:
                    expdate = re.search(r'Expdate[=:]"?([^",\n]+)"?', output, re.IGNORECASE)
                    if expdate:
                        exp_text = expdate.group(1).strip()
                        print(f"    > {nom} : {exp_text}")
                        any_found = True

            except Exception:
                pass

        if not any_found:
            print("    > Aucune licence avec date d'expiration trouvée (ou pas de licence active)")

        # Réseau
        print("\n--- [ RÉSEAU & INTERFACES ] ---")
        for line in iface_info.splitlines():
            if "type=Ethernet" in line:
                try:
                    p = {item.split('=')[0]: item.split('=')[1] for item in line.split() if '=' in item}
                    name = p.get('name', '???').split(',')[0]
                    addr = p.get('addr', 'No IP')
                    link = "LINK OK" if p.get('plugged') == "1" else "NO LINK"
                    
                    wan_tag = "[WAN] " if name.lower() == "out" or "ethernet0" in line.lower() else "      "
                    print(f"  {wan_tag} {name.upper():<10} | {addr:<18} | {link}")
                except:
                    pass

        print("\n" + "="*65)

    except Exception as e:
        print(f"\n[!] ERREUR : {e}")
    finally:
        try:
            client.disconnect()
        except:
            pass


if __name__ == "__main__":
    fetch_sns_stats()