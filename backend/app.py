from flask import Flask, request, jsonify, render_template, make_response
import requests, firebase_admin, os, tempfile
from firebase_admin import credentials, auth, firestore
from config import CLIENT_ID, CLIENT_SECRET, FOLDER_ID, FIREBASE_CONFIG

from google.oauth2 import service_account

from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)

firestore_db = firestore.client()

folder_id = "1XV2RurDdZAOol9yuYXxF9LE7RvwdA99v"

@app.route("/firebase-config")
def firebase_config():
    return jsonify(FIREBASE_CONFIG)

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
        #print(f"User ID: {uid}")

        private_key = generate_user_keys(uid) # creates encryption keys (if they don't already exist)

        response = {
            "message": "User verified", 
            "uid": uid, 
            "email": user_data.get("email"),
            "private_key": "",
        }
        
        if private_key != "keys already exist":
            response["private_key"] = private_key
            #print(f"{response["private_key"]}")

        response = make_response(jsonify(response))

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
    try:
        drive_service = get_drive_service()

        # list files from the shared folder
        query = f"'{FOLDER_ID}' in parents and trashed=false"
        results = drive_service.files().list(q=query).execute()

        files = results.get('files', [])

        return jsonify(files), 200

    except Exception as e:
        app.logger.error(f"Failed to fetch files: {e}")
        return jsonify({"error": "Failed to fetch files from Drive"}), 500

# create service to work with Drive API through service account
def get_drive_service():
    credentials = service_account.Credentials.from_service_account_file(
        "StorageDrive.json",
        scopes=['https://www.googleapis.com/auth/drive']
    )

    drive_service = build('drive', 'v3', credentials=credentials)
    return drive_service

# path to upload a file
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # use Python temp directory
    temp_dir = tempfile.gettempdir()
    file_path = os.path.join(temp_dir, file.filename)

    try:
        file.save(file_path) # save to temp

        service = get_drive_service()

        file_metadata = {
            'name': file.filename,
            'parents': [FOLDER_ID], # specify shared folder
        }

        # object to deal with Google Drive uploads
        media = MediaFileUpload(file_path, mimetype='application/octet-stream', resumable=True)

        uploaded_file = service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id, name, parents'
        ).execute() # upload file to specified folder

        # clean up
        del media
        os.remove(file_path)

        return jsonify({"message": f"{file.filename} uploaded successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

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

# creates RSA keys for the user and stores in firestore
def generate_user_keys(uid):
    # check database to see if keys already exist
    user_doc = firestore_db.collection("users").document(uid).get()
    if user_doc.exists and "public_key" in user_doc.to_dict():
        return "keys already exist"

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # format keys to allow storage
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # store keys
    firestore_db.collection("users").document(uid).set({"public_key": public_key_pem})

    return private_key_pem

if __name__ == "__main__":
    app.run(debug=True)