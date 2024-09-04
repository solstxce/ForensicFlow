from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_restx import Api, Resource, fields
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from bson import ObjectId
import email
from email import policy
from email.parser import BytesParser
import dns.resolver
import re

app = Flask(__name__)
api = Api(app, version='1.0', title='ForensicFlow API',
          description='A digital forensics API with email analysis capabilities')

# Configure MongoDB
app.config["MONGO_URI"] = "mongodb://localhost:27017/forensicflow"
mongo = PyMongo(app)

# Configure Bcrypt for password hashing
bcrypt = Bcrypt(app)

# Configure JWT
app.config["JWT_SECRET_KEY"] = "your-secret-key"  # Change this!
jwt = JWTManager(app)

# User roles
ROLES = ["Security Analyst", "Assistant Security Analyst", "Senior Security Analyst", "Security Analysis Supervisor", "Superuser"]

# Namespace
ns = api.namespace('api', description='ForensicFlow operations')

# Models
user_model = api.model('User', {
    'username': fields.String(required=True, description='User username'),
    'password': fields.String(required=True, description='User password'),
})

login_model = api.model('Login', {
    'username': fields.String(required=True, description='User username'),
    'password': fields.String(required=True, description='User password'),
})

role_change_model = api.model('RoleChange', {
    'user_id': fields.String(required=True, description='User ID'),
    'new_role': fields.String(required=True, description='New role'),
})

# Routes
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/register")
def register_page():
    return render_template("register.html")

@app.route("/dashboard")
@jwt_required()
def dashboard():
    return render_template("dashboard.html")

@ns.route('/register')
class Register(Resource):
    @api.expect(user_model)
    def post(self):
        """Register a new user"""
        users = mongo.db.users
        username = request.json["username"]
        password = request.json["password"]
        
        if users.find_one({"username": username}):
            return {"error": "Username already exists"}, 400
        
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        user_id = users.insert_one({
            "username": username,
            "password": hashed_password,
            "role": "Security Analyst"  # Default role
        }).inserted_id
        
        return {"message": "User created successfully"}, 201

@ns.route('/login')
class Login(Resource):
    @api.expect(login_model)
    def post(self):
        """Login and receive an access token"""
        users = mongo.db.users
        username = request.json["username"]
        password = request.json["password"]
        
        user = users.find_one({"username": username})
        if user and bcrypt.check_password_hash(user["password"], password):
            access_token = create_access_token(identity=str(user["_id"]))
            return {"access_token": access_token}, 200
        
        return {"error": "Invalid username or password"}, 401

@ns.route('/user_role')
class UserRole(Resource):
    @jwt_required()
    def get(self):
        """Get the role of the current user"""
        current_user_id = get_jwt_identity()
        user = mongo.db.users.find_one({"_id": ObjectId(current_user_id)})
        return {"role": user["role"]}

@ns.route('/analyze_mail')
class AnalyzeMail(Resource):
    @jwt_required()
    @api.expect(api.parser().add_argument('file', location='files', type='file', required=True))
    def post(self):
        """Analyze an email file"""
        if "file" not in request.files:
            return {"error": "No file provided"}, 400
        
        file = request.files["file"]
        if file.filename == "":
            return {"error": "No file selected"}, 400
        
        if file:
            eml_content = file.read()
            analysis_result = analyze_email(eml_content)
            return analysis_result, 200

@ns.route('/change_role')
class ChangeRole(Resource):
    @jwt_required()
    @api.expect(role_change_model)
    def post(self):
        """Change the role of a user (Superuser only)"""
        current_user_id = get_jwt_identity()
        current_user = mongo.db.users.find_one({"_id": ObjectId(current_user_id)})
        
        if current_user["role"] != "Superuser":
            return {"error": "Unauthorized"}, 403
        
        user_id = request.json["user_id"]
        new_role = request.json["new_role"]
        
        if new_role not in ROLES:
            return {"error": "Invalid role"}, 400
        
        result = mongo.db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"role": new_role}}
        )
        
        if result.modified_count:
            return {"message": "Role updated successfully"}, 200
        else:
            return {"error": "User not found"}, 404

@ns.route('/users')
class Users(Resource):
    @jwt_required()
    def get(self):
        """Get all users (Superuser only)"""
        current_user_id = get_jwt_identity()
        current_user = mongo.db.users.find_one({"_id": ObjectId(current_user_id)})
        
        if current_user["role"] != "Superuser":
            return {"error": "Unauthorized"}, 403
        
        users = list(mongo.db.users.find({}, {"password": 0}))
        for user in users:
            user["_id"] = str(user["_id"])
        
        return users

def analyze_email(eml_content):
    msg = BytesParser(policy=policy.default).parsebytes(eml_content)
    
    # Header analysis
    headers = dict(msg.items())
    
    # SPF check
    spf_result = check_spf(headers.get("Received-SPF", ""))
    
    # DKIM check
    dkim_result = check_dkim(headers.get("DKIM-Signature", ""))
    
    # DMARC check
    dmarc_result = check_dmarc(headers.get("From", ""))
    
    return {
        "subject": headers.get("Subject", ""),
        "from": headers.get("From", ""),
        "to": headers.get("To", ""),
        "date": headers.get("Date", ""),
        "spf_result": spf_result,
        "dkim_result": dkim_result,
        "dmarc_result": dmarc_result,
        "all_headers": headers
    }

def check_spf(spf_header):
    if not spf_header:
        return "No SPF record found"
    
    if "pass" in spf_header.lower():
        return "SPF check passed"
    else:
        return "SPF check failed"

def check_dkim(dkim_header):
    if not dkim_header:
        return "No DKIM signature found"
    
    # In a real scenario, you'd verify the DKIM signature here
    return "DKIM signature present, verification required"

def check_dmarc(from_header):
    domain = from_header.split("@")[-1].strip(">")
    try:
        dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        return "DMARC record found"
    except:
        return "No DMARC record found"

if __name__ == "__main__":
    app.run(debug=True)