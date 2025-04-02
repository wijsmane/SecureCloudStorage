from flask import Flask, request, jsonify, render_template, make_response, redirect
import requests
import firebase_admin
from firebase_admin import credentials, auth
from config import CLIENT_ID, CLIENT_SECRET

app = Flask(__name__)

cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)

@app.route('/')
def authentication():
    return render_template('authentication.html')

@app.route("/home")
def home():
    return render_template('home.html')

# POST method to verify the user with id token from firebase and store access/refresh tokens in cookies
@app.route("/verify-user", methods=["POST"])
def verify_user():
    data = request.get_json()
    id_token = data.get("idToken")
    access_token = data.get("accessToken")
    refresh_token = data.get("refreshToken")

    if not id_token:
        return jsonify({"message": "ID Token is missing"}), 400
    
    if not access_token:
        return jsonify({"message": "Access Token is missing"}), 400
    
    if not refresh_token:
        return jsonify({"message": "Refresh Token is missing"}), 400
    
    # check if the id token is valid
    user_data = verify_token(id_token)

    if user_data:
        uid = user_data["uid"]
        print(f"User ID: {uid}")

        response = make_response(jsonify({"message": "User verified", "uid": uid, "email": user_data.get("email")}))

        # store tokens for later use
        response.set_cookie("access_token", access_token, httponly=True, secure=False, samesite="Strict")
        response.set_cookie("refresh_token", refresh_token, httponly=True, secure=False, samesite="Strict")

        return response, 200
    else:
        return jsonify({"message": "Invalid or expired token"}), 401
    
# verify and decode provided token
def verify_token(id_token):
    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except Exception as e:
        app.logger.error(f"Authentication failed: {e}")
        return None

# get files from drive
@app.route("/get-drive-files", methods=["GET"])
def get_drive_files():
    access_token = request.cookies.get("access_token")
    refresh_token = request.cookies.get("refresh_token")

    if not access_token:
        app.logger.warning("refreshing access token")
        
        if not refresh_token:
            return jsonify({"error": "session expired, please re-authenticate"}), 401
        
        # get new access token if unavailable
        new_access_token = refresh_access_token(refresh_token)
        if not new_access_token:
            return jsonify({"error": "failed to refresh access token"}), 401

        app.logger.info("access token refreshed successfully")

        response = make_response(jsonify({"message": "access token refreshed, try again"}))
        # set cookie with refreshed access token
        response.set_cookie("access_token", new_access_token, httponly=True, secure=False, samesite="Strict")

        return response, 200

    # request from drive API using access token
    headers = {"Authorization": f"Bearer {access_token}"}
    google_drive_url = "https://www.googleapis.com/drive/v3/files"
    response_drive = requests.get(google_drive_url, headers=headers)

    if response_drive.status_code == 401:  # Token expired, refresh it
        return jsonify({"error": "access token expired, please re-authenticate"}), 401
    elif response_drive.status_code == 200:
        return jsonify(response_drive.json())
    else:
        return jsonify({"error": "failed to fetch files"}), response_drive.status_code

def refresh_access_token(refresh_token):
    url = "https://oauth2.googleapis.com/token"
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }

    # request new access token via Google OAuth
    response = requests.post(url, data=data)

    if response.status_code == 200:
        new_access_token = response.json().get("access_token")
        app.logger.info("refreshed access token")
        return new_access_token
    else:
        app.logger.error("could not refresh access token")
        return None

if __name__ == "__main__":
    app.run(debug=True)