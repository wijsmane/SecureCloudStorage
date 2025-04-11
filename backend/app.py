import logging, io, requests, firebase_admin, os, tempfile
from flask import Flask, request, jsonify, render_template, make_response, send_file, session
from firebase_admin import credentials, auth, firestore
from config import CLIENT_ID, CLIENT_SECRET, FOLDER_ID, FIREBASE_CONFIG, SECRET_KEY

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet

from ownca import CertificateAuthority

app = Flask(__name__)
app.secret_key = SECRET_KEY

ca = CertificateAuthority(ca_storage='/backend', common_name='LocalCA')

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
    try:
        app.logger.info("verifying")
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
            email = user_data["email"]
            #print(f"User ID: {uid}")

            # save for access to groups
            session["user"] = {
                "uid": user_data["uid"],
                "email": user_data["email"]
            }

            private_key = issue_user_certificate(uid, email) # issues cert and creates encryption keys (if they don't already exist)

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
    except Exception as e:
        app.logger.error(f"Error in verify_user: {str(e)}")  # Log any unexpected errors
        return jsonify({"message": "Internal Server Error"}), 500
    
# verify and decode provided token
def verify_token(id_token):
    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except Exception as e:
        app.logger.error(f"Authentication failed: {e}")
        return None
    
@app.route("/get-user-groups", methods=["GET"])
def get_user_groups():
    uid = session["user"]["uid"]
    groups_ref = firestore_db.collection("groups")
    user_groups = groups_ref.where("members", "array_contains", uid).stream()
    return jsonify([
        {"id": g.id, "name": g.to_dict().get("name", g.id)}
        for g in user_groups
    ])

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
    
@app.route("/download//<file_id>", methods=['GET'])
def download_file(file_id):
    try:
        drive_service = get_drive_service()
        
        # get the file name to ensure correct extension
        file_metadata = drive_service.files().get(fileId=file_id, fields='name').execute()
        filename = file_metadata.get('name', f"{file_id}.dat")  # default if name is missing

        # download file content into memory
        request = drive_service.files().get_media(fileId=file_id)
        file_stream = io.BytesIO()
        downloader = MediaIoBaseDownload(file_stream, request) # use the download object from Drive API

        done = False
        while not done:
            status, done = downloader.next_chunk()

        file_stream.seek(0)  # reset stream position for next download

        return send_file(
            file_stream,
            as_attachment=True,
            download_name=filename,  # keep correct extension using original name
            mimetype='application/octet-stream'
        )

    except Exception as e:
        app.logger.error(f"Error downloading file: {str(e)}")
        return jsonify({"error": "Failed to download file"}), 500
    
@app.route("/list-group-files/<group_id>", methods=["GET"])
def list_group_files(group_id):
    uid = session.get("uid")
    if not uid:
        return jsonify([]), 401

    # Fetch the group document
    group_ref = firestore_db.collection("groups").document(group_id).get()
    if not group_ref.exists:
        return jsonify({"error": "Group not found"}), 404

    group_data = group_ref.to_dict()
    if uid not in group_data.get("user_ids", []):
        return jsonify({"error": "Unauthorized"}), 403

    # Assuming files are stored as a list inside the group's document
    files = group_data.get("files", [])  
    return jsonify(files), 200
    

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

def issue_user_certificate(uid, email):
    user_doc = firestore_db.collection("users").document(uid).get()
    if user_doc.exists and "public_certificate" in user_doc.to_dict():
        return "keys already exist"

    # get certificate using ownca library with a placeholder hostname (as app is not deployed)
    hostname = f"{uid}.user.cert"
    cert_obj = ca.issue_certificate(
        hostname=hostname,
        dns_names=[hostname]
    )

    cert_pem = cert_obj.cert_bytes.decode("utf-8") # decode cert for storage / return

    # ownca uses the cryptogrpahy library to generate RSA keys, default exponent 65537 and size 2048
    private_key_pem = cert_obj.key_bytes.decode("utf-8")

    # ensure public key is stored in PEM format
    public_key = cert_obj.public_key 
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    # store cert and public key in database
    firestore_db.collection("users").document(uid).set({
        "email": email,
        "public_certificate": cert_pem,
        "public_key": public_key_pem
    })

    app.logger.info("issued cert and stored it")

    return private_key_pem  # send private key to frontend for user to download

@app.route("/create-group", methods=["POST"])
def create_group():
    try:
        data = request.json
        group_name = data.get("groupName")
        user_ids = data.get("userIds")  # list of Firebase user UIDs to be added to group

        if not group_name or not user_ids:
            return jsonify({"error": "missing group name or user IDs"}), 400

        # get AES key
        aes_key = Fernet.generate_key()

        encrypted_keys = {}
        for uid in user_ids:
            user_doc = firestore_db.collection("users").document(uid).get()
            if not user_doc.exists:
                app.logger.info(f"{uid} does not exist")
                continue

            user_data = user_doc.to_dict()
            public_key_pem = user_data.get("public_key").encode()
            public_key = serialization.load_pem_public_key(public_key_pem)

            # encrypt the AES key with the user's public key
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_keys[uid] = encrypted_aes_key.hex()  # Store as hex string

        # Store the group data
        group_data = {
            "name": group_name,
            "members": user_ids,
            "encrypted_keys": encrypted_keys
        }

        firestore_db.collection("groups").document(group_name).set(group_data)
        return jsonify({"message": "Group created successfully"}), 201

    except Exception as e:
        app.logger.error(f"Failed to create group: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(debug=True)
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
    app.logger.setLevel(logging.DEBUG)