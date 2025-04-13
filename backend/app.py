import logging, io, requests, firebase_admin, os, tempfile
from flask import Flask, request, jsonify, render_template, make_response, send_file, session
from firebase_admin import credentials, auth, firestore
from config import CLIENT_ID, CLIENT_SECRET, FOLDER_ID, FIREBASE_CONFIG, KEY

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet

from ownca import CertificateAuthority

app = Flask(__name__)
app.secret_key = KEY

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
            return jsonify({"message": "invalid or expired token"}), 401
    except Exception as e:
        app.logger.error(f"Error in verify_user: {str(e)}")
        return jsonify({"message": "Internal Server Error"}), 500
    
# verify and decode provided token
def verify_token(id_token):
    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except Exception as e:
        app.logger.error(f"Authentication failed: {e}")
        return None

# retrieve all groups that user is in
@app.route("/get-user-groups", methods=["GET"])
def get_user_groups():
    # get current user from session storage
    uid = session["user"]["uid"]
    groups_ref = firestore_db.collection("groups")
    user_groups = groups_ref.where("members", "array_contains", uid).stream()
    return jsonify([
        {"id": g.id, "name": g.to_dict().get("name", g.id)}
        for g in user_groups
    ])

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

    # get group info
    group_id = request.form.get("groupId")
    if not group_id:
        return jsonify({"error": "Group ID is required"}), 40
    group_doc = firestore_db.collection("groups").document(group_id).get()
    if not group_doc.exists:
        return jsonify({"error": "Group not found"}), 404
    
    # get file data
    if 'file' not in request.files:
        return jsonify({"error": "No file part in request"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # use Python temp directory
    temp_dir = tempfile.gettempdir()
    temp_file_path = os.path.join(temp_dir, file.filename)

    # get user session to retrieve this user's private key
    uid = session["user"]["uid"]

    try:
        # get private key that was uploaded by logged in user
        private_key = load_logged_in_private_key()

        # get AES key for the group by decrypting with user's private key
        group_doc = firestore_db.collection("groups").document(group_id).get()
        if not group_doc.exists:
            return jsonify({"error": "Group not found"}), 404
        encrypted_key_hex = group_doc.to_dict()["encrypted_keys"].get(uid)
        if not encrypted_key_hex:
            return jsonify({"error": "User not in group"}), 403
        encrypted_aes_key = bytes.fromhex(encrypted_key_hex)
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # encrypt file using Fernet with the decrypted AES group key
        fernet = Fernet(aes_key)
        encrypted_content = fernet.encrypt(file.read())

        with open(temp_file_path, "wb") as f:
            f.write(encrypted_content) # save to temp directory

        service = get_drive_service()

        file_metadata = {
            'name': file.filename,
            'parents': [FOLDER_ID], # specify shared folder
        }

        # object to deal with Google Drive uploads
        media = MediaFileUpload(temp_file_path, mimetype='application/octet-stream', resumable=True)

        uploaded_file = service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id, name, parents'
        ).execute() # upload file to specified folder

        # save data about the file to the group entry in database
        new_file_entry = {
            "id": uploaded_file.get("id"),  
            "name": uploaded_file.get("name"),
            "uploaded_by": session["user"]["uid"]
        }
        # using Firestore's array union to add the new file entry to an existing files list
        firestore_db.collection("groups").document(group_id).update({
            "files": firestore.ArrayUnion([new_file_entry])
        })

        # clean up
        del media
        os.remove(temp_file_path)

        return jsonify({"message": f"{file.filename} encrypted and uploaded successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# route to download a file from a specific group
@app.route("/download/<group_id>/<file_id>", methods=['GET'])
def download_file(group_id, file_id):
    try:
        # get private key
        uid = session["user"]["uid"]
        private_key = load_logged_in_private_key()

        # get group info
        group_doc = firestore_db.collection("groups").document(group_id).get()
        if not group_doc.exists:
            return jsonify({"error": "Group not found"}), 404
        group_data = group_doc.to_dict()
        encrypted_key_hex = group_data.get("encrypted_keys", {}).get(uid)
        if not encrypted_key_hex:
            return jsonify({"error": "User not in group or missing AES key"}), 403

        # decrypt group AES key using user's private key
        encrypted_aes_key = bytes.fromhex(encrypted_key_hex)
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        drive_service = get_drive_service()
        
        # get the file name to ensure correct extension when downloading
        file_metadata = drive_service.files().get(fileId=file_id, fields='name').execute()
        filename = file_metadata.get('name', f"{file_id}.dat")  # default if name is missing

        # download file content into memory
        request = drive_service.files().get_media(fileId=file_id)
        file_stream = io.BytesIO()
        downloader = MediaIoBaseDownload(file_stream, request) # use the download object from Drive API

        # keep downloading each chunk until none left
        done = False
        while not done:
            status, done = downloader.next_chunk()

        file_stream.seek(0)  # reset stream position for next download

        fernet = Fernet(aes_key)
        decrypted_content = fernet.decrypt(file_stream.read())

        # send_file method from flask to send to client
        return send_file(
            io.BytesIO(decrypted_content),
            as_attachment=True,
            download_name=filename,  # keep correct extension using original name
            mimetype='application/octet-stream'
        )
    except Exception as e:
        return jsonify({"error": "Failed to download file, may need to reupload private key"}), 500
    
# list files in a certain group (for display and then download)
@app.route("/list-group-files/<group_id>", methods=["GET"])
def list_group_files(group_id):
    # get current user
    uid = session.get("user", {}).get("uid")
    if not uid:
        return jsonify([]), 401

    # get group users
    group_ref = firestore_db.collection("groups").document(group_id).get()
    if not group_ref.exists:
        return jsonify({"error": "group not found"}), 404
    group_data = group_ref.to_dict()
    # make sure current user is in requested group
    if uid not in group_data.get("members", []):
        return jsonify({"error": "unauthorized, must be in group"}), 403

    # return list of files
    files = group_data.get("files", [])  
    return jsonify(files), 200
    
# refresh token to ensure access to Drive services
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

# function to issue certificates OwnCA library
def issue_user_certificate(uid, email):
    # if user has already logged in before, do not generate certificate and keys (they are stored already)
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

    # debug - ensure public key is stored in PEM format
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

    #app.logger.info("issued cert and stored it")
    return private_key_pem  # send private key to frontend for user to download and store securely themself

# create group based on user inputs
@app.route("/create-group", methods=["POST"])
def create_group():
    try:
        data = request.json
        group_name = data.get("groupName")
        user_ids = data.get("userIds")  # list of Firebase user UIDs to be added to group

        if not group_name or not user_ids:
            return jsonify({"error": "missing group name or user IDs"}), 400

        # get AES key that will be used to encrypt all files for the group
        aes_key = Fernet.generate_key()

        # encrypt the AES key with each user's public key
        encrypted_keys = {}
        for uid in user_ids:
            user_doc = firestore_db.collection("users").document(uid).get()
            if not user_doc.exists:
                app.logger.info(f"{uid} does not exist")
                continue

            # load public key
            user_data = user_doc.to_dict()
            public_key_pem = user_data.get("public_key").encode()
            public_key = serialization.load_pem_public_key(public_key_pem)

            # encrypt
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_keys[uid] = encrypted_aes_key.hex()  # store as hex string

        # store the group data
        group_data = {
            "name": group_name,
            "members": user_ids,
            "encrypted_keys": encrypted_keys,
            "files" : [] # placeholder for eventual file information
        }

        # save to database
        firestore_db.collection("groups").document(group_name).set(group_data)
        return jsonify({"message": "Group created successfully"}), 201
    except Exception as e:
        app.logger.error(f"Failed to create group: {e}")
        return jsonify({"error": "Internal server error"}), 500
    
# add user to an existing group
@app.route("/add-user-to-group", methods=["POST"])
def add_user_to_group():
    try:
        data = request.get_json()
        group_id = data.get("groupId")
        new_user_id = data.get("userId")
        

        uid = session["user"]["uid"]
        private_key = load_logged_in_private_key()

        group_ref = firestore_db.collection("groups").document(group_id)
        group_doc = group_ref.get()
        if not group_doc.exists:
            return jsonify({"error": "Group does not exist"}), 404

        group_data = group_doc.to_dict()
        encrypted_keys = group_data["encrypted_keys"]

        # decrypt group's AES key using the logged in user's private key
        encrypted_key_hex = encrypted_keys.get(uid)
        if not encrypted_key_hex:
            return jsonify({"error": "You don't have access to this group"}), 403
        
        aes_key = private_key.decrypt(
            bytes.fromhex(encrypted_key_hex),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # get new user's public key
        new_user_doc = firestore_db.collection("users").document(new_user_id).get()
        if not new_user_doc.exists:
            return jsonify({"error": "New user does not exist"}), 404

        public_key_pem = new_user_doc.to_dict()["public_key"].encode()
        public_key = serialization.load_pem_public_key(public_key_pem)

        # encrypt group AES key for new user
        encrypted_for_new_user = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # update group entry in database
        firestore_db.collection("groups").document(group_id).update({
            "members": firestore.ArrayUnion([new_user_id]),
            f"encrypted_keys.{new_user_id}": encrypted_for_new_user.hex()
        })

        return jsonify({"message": "User added to group successfully"}), 200

    except Exception as e:
        app.logger.error(f"Failed to add user: {e}")
        return jsonify({"error": "Internal server error"}), 500

# remove user from a specified group, generate a new AES key, re-encrypt files, and store new keys
@app.route("/remove-user-from-group", methods=["POST"])
def remove_user_from_group():
    try:
        data = request.json
        group_name = data.get("groupName")
        user_id = data.get("userId")

        if not group_name or not user_id:
            return jsonify({"error": "Missing group ID or user ID"}), 400

        group_ref = firestore_db.collection("groups").document(group_name)
        group_doc = group_ref.get()

        if not group_doc.exists:
            return jsonify({"error": "Group not found"}), 404

        # get the member, encrypted_keys, and files in the group
        group_data = group_doc.to_dict()
        members = group_data.get("members", [])
        encrypted_keys = group_data.get("encrypted_keys", {})
        files = group_data.get("files", []) 

        # if user to remove is not in the group, exit
        if user_id not in members:
            return jsonify({"error": "User not in group"}), 400

        members.remove(user_id)
        encrypted_keys.pop(user_id, None)

        # if group is now empty do not try to re-encrypt
        if not members:
            return jsonify({"error": "At least one member must remain"}), 400

        # load old AES key by using the current user's private key
        aes_key = None
        for uid, encrypted_key_hex in encrypted_keys.items():
            private_key = load_logged_in_private_key()
            encrypted_aes_key = bytes.fromhex(encrypted_key_hex)
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            break  # only need to do this once to get the AES key

        if not aes_key:
            return jsonify({"error": "AES key not found"}), 400

        fernet = Fernet(aes_key)
        drive_service = get_drive_service()

        # decrypt each file
        decrypted_files = []
        for file in files:
            file_id = file.get("id")
            # use Drive to download each file
            req = drive_service.files().get_media(fileId=file_id)
            file_stream = io.BytesIO()
            downloader = MediaIoBaseDownload(file_stream, req)
            done = False
            while not done:
                _, done = downloader.next_chunk()
            file_stream.seek(0) # reset
            # decrypt with AES key
            decrypted_data = fernet.decrypt(file_stream.read())
            decrypted_files.append((file_id, decrypted_data))

        # generate a new AES key and re-encrypt files
        new_aes_key = Fernet.generate_key()
        new_fernet = Fernet(new_aes_key)

        for file_id, decrypted_data in decrypted_files:
            reencrypted_data = new_fernet.encrypt(decrypted_data)
            # save re-encrypted file to a temp file
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(reencrypted_data)
                temp_file_path = temp_file.name

            # create MediaFileUpload (Drive object for handling upload) with the temp file path
            media_body = MediaFileUpload(temp_file_path, mimetype='application/octet-stream')

            # upload file back to Drive, overwriting the previous version
            drive_service.files().update(fileId=file_id, media_body=media_body).execute()

            # clean up temp file
            del media_body
            os.remove(temp_file_path)

        # encrypt new AES key for remaining users
        new_encrypted_keys = {}
        for member_uid in members:
            user_doc = firestore_db.collection("users").document(member_uid).get()
            if user_doc.exists:
                public_key_pem = user_doc.to_dict().get("public_key").encode()
                public_key = serialization.load_pem_public_key(public_key_pem)

                encrypted_aes_key = public_key.encrypt(
                    new_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                new_encrypted_keys[member_uid] = encrypted_aes_key.hex()

        # update group document with new keys
        group_ref.update({
            "members": members,
            "encrypted_keys": new_encrypted_keys
        })

        return jsonify({"message": f"User {user_id} removed and files re-encrypted"}), 200

    except Exception as e:
        app.logger.error(f"Failed to remove user from group: {e}")
        return jsonify({"error": "Internal server error"}), 500

# route to temporarily save private key that user uploads
@app.route("/upload-private-key", methods=["POST"])
def upload_private_key():
        if "private_key" not in request.files:
            return jsonify({"error": "No key file uploaded"}), 400

        pk_file = request.files["private_key"]
        if pk_file.filename == "":
            return jsonify({"error": "Empty filename"}), 400

        uid = session.get("user", {}).get("uid")
        if not uid:
            return jsonify({"error": "User not authenticated"}), 401

        # save private key in temp directory
        temp_dir_key = tempfile.gettempdir()
        key_path = os.path.join(temp_dir_key, f"{uid}_private.pem")

        try:
            pk_file.save(key_path)
            session["private_key_path"] = key_path  # store key for next action
            return jsonify({"message": "Private key uploaded successfully"}), 200
        except Exception as e:
            app.logger.error(f"Error saving private key: {e}")
            return jsonify({"error": "Failed to store private key"}), 500
        
# function to load private key
def load_logged_in_private_key():
    uid = session.get("user", {}).get("uid")
    key_path = session.get("private_key_path")

    if not uid or not key_path or not os.path.exists(key_path):
        raise Exception("Private key not found for user session")

    with open(key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    del session["private_key_path"] # now delete - requires reupload of private key before every action
    
    return private_key

if __name__ == "__main__":
    app.run(debug=True)
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
    app.logger.setLevel(logging.DEBUG)