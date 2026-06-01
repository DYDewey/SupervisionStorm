from flask import Flask, render_template, request
from collector import collecter_firewall

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        host = request.form.get("host")
        user = request.form.get("user")
        password = request.form.get("password")
        port = request.form.get("port")
        try:
            if not port:
                port = 443
            else:
                port = int(port)
            resultat = collecter_firewall(host, user, password, port)
            return render_template("resultat.html", resultat=resultat)
        except ValueError:
            return render_template(
                "resultat.html",
                resultat={
                    "host": host,
                    "statut": "KO",
                    "erreur": "Le port doit être un nombre valide."
                }
            )
        except Exception as e:
            erreur_utilisateur = traduire_erreur(e)
            return render_template(
                "resultat.html",
                resultat={
                    "host": host,
                    "statut": "KO",
                    "erreur": erreur_utilisateur
                }
            )
    return render_template("index.html")

def traduire_erreur(exception):
    message = str(exception)
    if "NameResolutionError" in message or "getaddrinfo failed" in message:
        return "Nom d’hôte ou adresse IP invalide."
    if "Max retries exceeded" in message or "Connection refused" in message:
        return "Pare-feu inaccessible ou service d'administration indisponible."
    if "401" in message or "403" in message:
        return "Identifiants invalides ou accès refusé."
    if "SSLError" in message or "ssl" in message.lower():
        return "Erreur SSL lors de la connexion au pare-feu."
    return "Une erreur est survenue lors de la connexion au pare-feu."

if __name__ == "__main__":
    app.run(debug=True)