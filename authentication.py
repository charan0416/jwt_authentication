from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)

# Secret key for encoding the JWTs
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # Change this to something more secure

jwt = JWTManager(app)

# In-memory user data (replace with a database in production)
users_db = {
    "testuser": {
        "password": "password123"
    }
}

# Login endpoint to authenticate and generate JWT token
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if username in users_db and users_db[username]['password'] == password:
        # Create an access token with the username
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"msg": "Bad username or password"}), 401

# Protected route requires JWT token for access
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    # Get the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

if __name__ == '__main__':
    app.run(debug=True)
