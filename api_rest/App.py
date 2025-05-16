from flask import Flask,request, jsonify
import psycopg2
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from functools import wraps
from datetime import datetime, timezone
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['JWT_SECRET_KEY'] = 'Azoupro8323'  # 🔐 Mets une vraie clé secrète ici
app.config["JWT_IDENTITY_CLAIM"] = "identity"  # 🔥 Autorise les dictionnaires
jwt = JWTManager(app) 


@app.route("/test_db")
def test_db_connection():
    try:
        conn = psycopg2.connect(
            host="localhost",
            dbname="projet_api_rest",
            user="azoupro",
            password=" "
        )
        conn.close()
        return jsonify({"status": "success", "message": "Connexion réussie à PostgreSQL"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

def get_db_connection():
    return psycopg2.connect(
        host="localhost",
        database="projet_api_rest",     
        user="azoupro",
        password=" "
    )
def role_require(require_role):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            print(verify_jwt_in_request)
            identity = get_jwt_identity()
            if identity.get("role") != require_role:
                return jsonify({"msg": f"⛔ Accès refusé : réservé au rôle '{require_role}'"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    mot_passe = data.get("mot_passe")

    conn = get_db_connection()
    cur = conn.cursor()
    # ✅ Sélectionne aussi id_user !
    cur.execute(
        "SELECT id_user, mot_passe, role FROM Utilisateur WHERE email = %s",
        (email,)
    )
    result = cur.fetchone()
    cur.close()
    conn.close()

    if result is None:
        return jsonify({"msg": "❌ Utilisateur introuvable"}), 401

    id_user, hashed_password, role = result

    if bcrypt.check_password_hash(hashed_password, mot_passe):
        access_token = create_access_token(identity={
            "id_user": id_user,
            "email": email,
            "role": role
        })
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "❌ Mot de passe invalide"}), 401


@app.route('/admin', methods=['GET'])
@role_require("admin")
def admin_only():
    return jsonify({"msg": "✅ Bienvenue, Admin !"})

@app.route('/user', methods=['GET'])
@role_require("utilisateur")
def user_only():
    return jsonify({"msg": "👋 Bonjour, utilisateur normal"})

INSERT_utilisateur_RETURN_ID = """
INSERT INTO Utilisateur (nom, email, mot_passe, role) 
VALUES (%s, %s, %s, %s) 
RETURNING id_user;
"""

@app.route("/Creer_Utilisateur", methods=['POST'])
@role_require("admin")
def Inserer_Utilisateur():
    data = request.get_json()
    nom = data["nom"]
    email = data["email"]
    mot_passe = data["mot_passe"]
     
    role = "user"
    # Hash du mot de passe
    hashed_pw = bcrypt.generate_password_hash(mot_passe).decode('utf-8')

    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute(INSERT_utilisateur_RETURN_ID, (nom, email, hashed_pw, role))
    id_user = cur.fetchone()[0]
    conn.commit()  # N'oublie pas !

    cur.close()
    conn.close()

    return jsonify({
        "id_utilisateur": id_user,
        "nom_utilisateur": nom,
        "email_utilisateur": email
    }), 201

INSERT_Groupe_RETURN_ID = """
INSERT INTO groupe (nom) 
VALUES (%s) 
RETURNING id_group;
"""

@app.route("/creer_groupe", methods=['POST'])
@role_require("admin")
def creer_groupe():
    data = request.get_json()
    nom = data["nom"]

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(INSERT_Groupe_RETURN_ID, (nom,))
    id_group = cur.fetchone()[0]
    conn.commit()

    cur.close()
    conn.close()

    return jsonify({
        "id_groupe": id_group,
        "nom_groupe": nom
    }), 201

INSERT_Groupe_Utilisateur_RETURN_ID = """
INSERT INTO utilisateur_groupe (id_user, id_group) 
VALUES (%s, %s) 
RETURNING id_user, id_group;
"""

@app.route("/associer_utilisateur_groupe", methods=['POST'])
@role_require("admin")
def associer_utilisateur_groupe():
    data = request.get_json()
    id_user = data["id_user"]
    id_group = data["id_group"]

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(INSERT_Groupe_Utilisateur_RETURN_ID, (id_user, id_group))
    result = cur.fetchone()
    conn.commit()

    cur.close()
    conn.close()

    return jsonify({
        "msg": "✅ Utilisateur associé au groupe",
        "id_utilisateur": result[0],
        "id_groupe": result[1]
    }), 201

Supprimer_prompt = """DELETE FROM prompt WHERE id_prompt = %s"""

@app.route("/supprimer_prompt/<int:id_prompt>", methods=['DELETE'])
@role_require("admin")
def supprimer_prompt(id_prompt):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(Supprimer_prompt, (id_prompt,))
    conn.commit()  # Important pour valider la suppression

    cur.close()
    conn.close()

    return jsonify({"msg": f"✅ Prompt avec ID {id_prompt} supprimé."}), 200
SQL_VOIR_TOUS_PROMPTS = """SELECT * FROM prompt"""

@app.route("/voir_tous_prompt", methods=['GET'])
@role_require("admin")

def voir_tous_les_prompts():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(SQL_VOIR_TOUS_PROMPTS)
    prompts = cur.fetchall()

    # Récupère les noms de colonnes pour construire un dictionnaire propre
    colonnes = [desc[0] for desc in cur.description]
    prompts_dict = [dict(zip(colonnes, ligne)) for ligne in prompts]

    cur.close()
    conn.close()

    return jsonify(prompts_dict), 200
INSERT_Prompt_Par_utilisateur_RETURN_ID = """
INSERT INTO Utilisateur (titre, contenu, prix, etat, date_creation) 
VALUES (%s, %s, %s,"en attente", %s) 
RETURNING id_prompt;
"""

INSERT_Prompt_Par_utilisateur_RETURN_ID = """
INSERT INTO prompt (titre, contenu, prix, etat, date_creation, id_user)
VALUES (%s, %s, %s, %s, %s, %s)
RETURNING id_prompt;
"""

@app.route("/ajouter_prompts", methods=['POST'])
@role_require("utilisateur")
def ajouter_prompt():
    data = request.get_json()
    titre = data.get("titre")
    contenu = data.get("contenu")
    prix = data.get("prix")
    etat = "En attente"
    try:
        date_creation = datetime.strptime(data.get("date_creation", ""), "%m-%d-%Y %H:%M:%S")
    except (KeyError, ValueError, TypeError):
        date_creation = datetime.now(timezone.utc)

    identity = get_jwt_identity()
    id_user = identity.get("id_user")  # Assure-toi que ce champ est bien dans ton JWT

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(INSERT_Prompt_Par_utilisateur_RETURN_ID,
                (titre, contenu, prix, etat, date_creation, id_user))
    id_prompt = cur.fetchone()[0]
    conn.commit()

    cur.close()
    conn.close()

    return jsonify({
        "id_prompt": id_prompt,
        "msg": "✅ Prompt ajouté avec succès"
    }), 201

@app.route("/visiteur/<int:id_prompt>", methods=['GET'])
def consulter_prompt():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(SQL_VOIR_TOUS_PROMPTS)
    prompts = cur.fetchall()

    # Récupère les noms de colonnes pour construire un dictionnaire propre
    colonnes = [desc[0] for desc in cur.description]
    prompts_dict = [dict(zip(colonnes, ligne)) for ligne in prompts]

    cur.close()
    conn.close()

    return jsonify(prompts_dict), 200
SQL_RECHERCHE_PAR_CONTENU = """SELECT * FROM prompt WHERE contenu ILIKE %s"""

@app.route("/recherche_par_son_contenu/<string:contenu>")
def recherche_prompt(contenu):
    conn = get_db_connection()
    cur = conn.cursor()

    # ⚠️ Passe le paramètre dans un tuple (contenu,)
    cur.execute(SQL_RECHERCHE_PAR_CONTENU, (f"%{contenu}%",))
    prompts = cur.fetchall()

    colonnes = [desc[0] for desc in cur.description]
    prompts_dict = [dict(zip(colonnes, ligne)) for ligne in prompts]

    cur.close()
    conn.close()

    return jsonify(prompts_dict), 200
if __name__ == "__main__":
	app.run(debug=True)