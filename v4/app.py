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

        if not port:
            port = 443
        else:
            port = int(port)

        resultat = collecter_firewall(host, user, password, port)
        return render_template("resultat.html", resultat=resultat)

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)