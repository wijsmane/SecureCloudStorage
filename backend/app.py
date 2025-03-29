from flask import Flask, request, jsonify
import firebase_admin
from firebase_admin import credentials, auth

app = Flask(__name__)

cred = credentials.Certificate("path/to/serviceAccountKey.json")
firebase_admin.initialize_app(cred)

@app.route("/upload")
def upload_file():
    return "<p>Hello, World!</p>"

# POST method to verify the user with token from firebase
@app.route("/verify-user", methods=["POST"])
def verify_user():
    data = request.get_json()
    id_token = data.get("idToken")

    user_data = verify_token(id_token)
    if user_data:
        return jsonify({"message": "User verified", "uid": user_data["uid"], "email": user_data.get("email")}), 200
    else:
        return jsonify({"message": "Invalid or expired token"}), 401
    
# checks provided token
def verify_token(id_token):
    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except Exception as e:
        app.logger.error(f"Authentication failed: {e}")
        return None

if __name__ == "__main__":
    app.run(debug=True)