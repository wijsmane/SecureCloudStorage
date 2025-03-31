from flask import Flask, request, requests, jsonify, render_template, make_response
import firebase_admin
from firebase_admin import credentials, auth

app = Flask(__name__)

cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)

@app.route('/')
def home():
    return render_template('authentication.html')

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
        uid = user_data["uid"]

        # get Google Drive access token from request (if available)
        access_token = data.get("accessToken")

        response = make_response(jsonify({"message": "user verified", "uid": uid, "email": user_data.get("email")}))
        
        if access_token:
            response.set_cookie(
                "access_token", 
                access_token, 
                httponly=True,  # not accessible via JavaScript
                secure=True,    # use HTTPS in production
                samesite="Strict"
            )

        return response, 200
    else:
        return jsonify({"message": "invalid or expired token"}), 401
    
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