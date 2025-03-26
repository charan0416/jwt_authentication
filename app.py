from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
import os
from dotenv import load_dotenv
from datetime import timedelta
from flask_jwt_extended import exceptions
from flask_bcrypt import Bcrypt

load_dotenv()

app = Flask(__name__)

bcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')  # This is for Flask session management
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')  # This is for JWT signing
app.config["SECRET_KEY"] = "HS256"

app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=2)  # Access token expires in 15 minutes
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=3)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'


db = SQLAlchemy()
db.init_app(app)
jwt = JWTManager(app)



class Login_user(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(20), nullable=False)

    def __str__(self):
        return f"username: {self.username}"


@app.route('/adduser', methods=['POST'])
def adding_user():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        # Check if both username and password are provided
        if not username or not password:
            return jsonify({"message": "Missing username or password"}), 400

        # Create a new user instance

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = Login_user(username=username, password=hashed_password)

        # Add the new user to the database
        db.session.add(user)
        db.session.commit()

        return jsonify({"message": "User added successfully"}), 201

    except Exception as e:

        print(f"Error occurred: {str(e)}")
        return jsonify({"message": "An error occurred while adding the user"}), 500


@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()

    # Extract username and password from the request data
    username = data.get('username')
    password = data.get('password')

    user = Login_user.query.filter_by(username=username).first()

    if user is None or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"message": "Invalid username or password"}), 401

    # Create JWT tokens for the authenticated user
    access_token = create_access_token(identity=username)
    refresh_token = create_refresh_token(identity=username)

    return jsonify({
        "message": "Login successful",
        "access_token": access_token,
        "refresh_token": refresh_token
    }), 200


@app.route('/resetpassword', methods=['PUT'])
@jwt_required()
def reset_password():
    try:
        # Get data from request
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')


        if not username or not password:
            return jsonify({"message": "Username and password are required"}), 400


        check_user = Login_user.query.filter_by(username=username).first()

        if check_user:
            # Update password if user exists
            updated_password = bcrypt.generate_password_hash(password).decode('utf-8')
            check_user.password = updated_password
            db.session.commit()

            return jsonify({"message": "Password updated successfully"}), 200  # 200 OK status
        else:

            return jsonify({"message": "User not found"}), 404  # 404 Not Found

    except Exception as e:
        # Handle other exceptions
        print(f"Error occurred: {str(e)}")
        return jsonify({"error": str(e)}), 500  # Internal Server Error


@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    try:
        current_user = get_jwt_identity()  # Get the username from the refresh token
        new_access_token = create_access_token(identity=current_user)  # Generate a new access token

        return jsonify({
            "message": "Access token refreshed",
            "access_token": new_access_token
        }), 200
    except exceptions.ExpiredSignatureError:
        return jsonify({"message": "Refresh token has expired"}), 401
    except exceptions.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 401


if __name__ == '__main__':
    app.run(debug=True)
