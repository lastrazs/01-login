"""Python Flask WebApp Auth0 integration example with proper user metadata handling"""
import json
from os import environ as env
from urllib.parse import quote_plus, urlencode
import requests
from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, render_template, request, session, url_for, flash

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")

oauth = OAuth(app)

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

def get_management_api_token():
    """Obtiene token de acceso para la API de Management de Auth0"""
    try:
        domain = env.get("AUTH0_DOMAIN")
        if not domain:
            raise ValueError("AUTH0_DOMAIN no está configurado en las variables de entorno")
        
        client_id = env.get("AUTH0_CLIENT_ID")
        if not client_id:
            raise ValueError("AUTH0_CLIENT_ID no está configurado en las variables de entorno")
        
        client_secret = env.get("AUTH0_CLIENT_SECRET")
        if not client_secret:
            raise ValueError("AUTH0_CLIENT_SECRET no está configurado en las variables de entorno")
        
        url = f"https://{domain}/oauth/token"
        payload = {
            "client_id": client_id,
            "client_secret": client_secret,
            "audience": f"https://{domain}/api/v2/",
            "grant_type": "client_credentials"
        }
        
        response = requests.post(url, json=payload)
        
        if response.status_code != 200:
            error_details = response.json()
            raise Exception(
                f"Error al obtener token de Management API. "
                f"Status: {response.status_code}. "
                f"Error: {error_details.get('error', 'desconocido')}. "
                f"Descripción: {error_details.get('error_description', 'sin descripción')}"
            )
        
        return response.json().get("access_token")
    
    except Exception as e:
        print(f"Error detallado al obtener token de Management API: {str(e)}")
        raise
    
    
def get_user_metadata(user_id):
    """Obtiene los metadatos del usuario desde Auth0"""
    try:
        token = get_management_api_token()
        domain = env.get("AUTH0_DOMAIN")
        url = f"https://{domain}/api/v2/users/{user_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            user_data = response.json()
            return user_data.get("user_metadata", {})
        elif response.status_code == 401:
            raise Exception("Token de acceso no válido o expirado")
        elif response.status_code == 403:
            raise Exception("Permisos insuficientes para acceder a este recurso")
        else:
            raise Exception(f"Error al obtener metadatos: {response.status_code} - {response.text}")
    
    except Exception as e:
        print(f"Error detallado al obtener metadatos del usuario: {str(e)}")
        return {}
    
# Controllers API
@app.route("/")
def home():
    return render_template(
        "home.html",
        session=session.get("user"),
        pretty=json.dumps(session.get("user"), indent=4),
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    
    # Obtener metadata del usuario después del login
    user_id = token.get("userinfo", {}).get("sub")
    if user_id:
        user_metadata = get_user_metadata(user_id)
        if user_metadata:
            token["userinfo"]["user_metadata"] = user_metadata
            session["user"] = token
    
    return redirect("/")

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

@app.route("/profile")
def profile():
    user = session.get("user")
    if not user:
        return redirect("/login")
    
    # Obtener metadata actualizada del usuario
    user_id = user.get("userinfo", {}).get("sub")
    user_metadata = {}
    
    if user_id:
        user_metadata = get_user_metadata(user_id)
        # Actualizar la sesión con los metadatos más recientes
        if user_metadata:
            user["userinfo"]["user_metadata"] = user_metadata
            session["user"] = user
    
    return render_template(
        "profile.html",
        user_metadata=user_metadata,
        user=user.get("userinfo")
    )

@app.route("/update_profile", methods=["POST"])
def update_profile():
    user = session.get("user")
    if not user:
        return redirect("/login")
    
    try:
        # Obtener token de acceso para Management API
        token = get_management_api_token()
        user_id = user.get("userinfo", {}).get("sub")
        
        if not user_id:
            flash("Error: No se pudo identificar al usuario", "error")
            return redirect("/profile")
        
        # Preparar datos del formulario
        user_metadata = {
            "doc_type": request.form.get("doc_type"),
            "doc_number": request.form.get("doc_number"),
            "address": request.form.get("address"),
            "phone": request.form.get("phone")
        }
        
        # Actualizar usuario en Auth0
        domain = env.get("AUTH0_DOMAIN")
        url = f"https://{domain}/api/v2/users/{user_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        # El payload debe contener solo user_metadata
        payload = {
            "user_metadata": user_metadata
        }
        
        response = requests.patch(url, headers=headers, json=payload)
        
        if response.status_code == 200:
            # Actualizar la sesión con los nuevos datos
            user["userinfo"]["user_metadata"] = user_metadata
            session["user"] = user
            flash("Perfil actualizado correctamente", "success")
        else:
            error_msg = response.json().get("message", "Error desconocido al actualizar el perfil")
            flash(f"Error al actualizar: {error_msg}", "error")
    
    except Exception as e:
        flash(f"Error al actualizar el perfil: {str(e)}", "error")
    
    return redirect("/profile")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=env.get("PORT", 3000))