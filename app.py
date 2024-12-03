from flask import Flask, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt

# Initialize Flask app and extensions
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///rbac.db'  # Database URI
app.config['SECRET_KEY'] = 'mysecretkey'  # Secret key for JWT
app.config['JWT_SECRET_KEY'] = 'jwtsecretkey'  # Secret key for JWT
db = SQLAlchemy(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# Database Models

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    role = db.relationship('Role', backref='users')

# Create the database tables
with app.app_context():
    db.create_all()

# Routes for Authentication and Authorization

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role_name = data.get('role')  # Role passed during registration (admin, user, etc.)

    # Check if user already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"message": "User already exists!"}), 400

    # Hash the password
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Assign the role
    role = Role.query.filter_by(name=role_name).first()
    if not role:
        return jsonify({"message": "Role not found!"}), 400

    new_user = User(username=username, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User created successfully!"}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Find the user in the database
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"message": "User not found!"}), 404

    # Check if the password matches
    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"message": "Invalid password!"}), 401

    # Create JWT token
    access_token = create_access_token(identity={'username': user.username, 'role': user.role.name})
    return jsonify({"access_token": access_token}), 200


@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    if current_user['role'] == 'Admin':
        return jsonify({"message": "Welcome Admin, you can manage everything!"}), 200
    elif current_user['role'] == 'User':
        return jsonify({"message": "Welcome User, you can view content!"}), 200
    else:
        return jsonify({"message": "Access Denied!"}), 403


@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    # Here we will simply send a response that the user has logged out
    return jsonify({"message": "User logged out!"}), 200

if __name__ == '__main__':
    app.run(debug=True)
