from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, Blueprint
from flask_restx import Api, Resource, fields, Namespace
from flask_pymongo import PyMongo
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from bson import ObjectId
import email
from email import policy
from email.parser import BytesParser
import dns.resolver
import re
from functools import wraps

app = Flask(__name__)
authorizations = {
    'Bearer Auth': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization'
    },
}

# Create a Blueprint for the API
api_bp = Blueprint('api', __name__, url_prefix='/api')
api = Api(api_bp, version='1.0', title='ForensicFlow API',
          description='A digital forensics API with email analysis capabilities',
          authorizations=authorizations,
          security='Bearer Auth',
          doc='/docs')  # Swagger UI will be available at /api/docs

# Register the Blueprint with the app
app.register_blueprint(api_bp)

# Configure MongoDB
app.config["MONGO_URI"] = "mongodb://localhost:27017/forensicflow"
app.config["SECRET_KEY"] = "your-secret-key"  # Change this!
mongo = PyMongo(app)

# Configure Bcrypt for password hashing
bcrypt = Bcrypt(app)

# Configure JWT
app.config["JWT_SECRET_KEY"] = "your-jwt-secret-key"  # Change this!
jwt = JWTManager(app)

# User roles and permissions
ROLES = {
    "Security Analyst": ["analyze_email"],
    "Assistant Security Analyst": ["analyze_email"],
    "Senior Security Analyst": ["analyze_email", "view_all_analyses"],
    "Security Analysis Supervisor": ["analyze_email", "view_all_analyses", "manage_analysts"],
    "Superuser": ["analyze_email", "view_all_analyses", "manage_analysts", "manage_users"]
}

# Decorator for role-based access control
def role_required(required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user_id = get_jwt_identity()
            current_user = mongo.db.users.find_one({"_id": ObjectId(current_user_id)})
            if current_user["role"] not in required_roles:
                return {"error": "Unauthorized"}, 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Namespaces
auth_ns = Namespace('auth', description='Authentication operations')
user_ns = Namespace('user', description='User operations')
email_ns = Namespace('email', description='Email analysis operations')

api.add_namespace(auth_ns)
api.add_namespace(user_ns)
api.add_namespace(email_ns)

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

action_password_model = api.model('ActionPassword', {
    'password': fields.String(required=True, description='Action password'),
})

# Routes

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/login", methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = mongo.db.users.find_one({"username": username})
        if user and bcrypt.check_password_hash(user["password"], password):
            if not user.get("approved", False):
                flash("Your account is pending approval.", "warning")
                return redirect(url_for('login_page'))
            access_token = create_access_token(identity=str(user["_id"]))
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "error")
    return render_template("login.html")

@app.route("/register", methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for('register_page'))
        
        if mongo.db.users.find_one({"username": username}):
            flash("Username already exists", "error")
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            mongo.db.users.insert_one({
                "username": username,
                "password": hashed_password,
                "role": "Pending Approval",
                "approved": False
            })
            flash("User created successfully. Waiting for admin approval.", "success")
            return redirect(url_for('login_page'))
    return render_template("register.html")

@app.route("/dashboard")
@jwt_required()
def dashboard():
    current_user_id = get_jwt_identity()
    current_user = mongo.db.users.find_one({"_id": ObjectId(current_user_id)})
    return render_template("dashboard.html", user_role=current_user["role"])

@app.route("/ea-dashboard")
@jwt_required()
def ea_dashboard():
    return render_template("ea-dashboard.html")

# API routes
@auth_ns.route('/register')
class Register(Resource):
    @api.expect(user_model)
    @api.doc(responses={201: 'User created successfully', 400: 'Username already exists'})
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
            "role": "Pending Approval",
            "approved": False
        }).inserted_id
        
        return {"message": "User created successfully. Waiting for admin approval."}, 201

@auth_ns.route('/login')
class Login(Resource):
    @api.expect(login_model)
    @api.doc(responses={200: 'Login successful', 401: 'Invalid username or password', 403: 'Account not approved'})
    def post(self):
        """Login and receive an access token"""
        users = mongo.db.users
        username = request.json["username"]
        password = request.json["password"]
        
        user = users.find_one({"username": username})
        if user and bcrypt.check_password_hash(user["password"], password):
            if not user.get("approved", False):
                return {"error": "Your account is pending approval."}, 403
            access_token = create_access_token(identity=str(user["_id"]))
            return {"access_token": access_token, "role": user["role"]}, 200
        
        return {"error": "Invalid username or password"}, 401

@user_ns.route('/role')
class UserRole(Resource):
    @jwt_required()
    @api.doc(security='Bearer Auth')
    def get(self):
        """Get the role of the current user"""
        current_user_id = get_jwt_identity()
        user = mongo.db.users.find_one({"_id": ObjectId(current_user_id)})
        return {"role": user["role"]}

@user_ns.route('/change_role')
class ChangeRole(Resource):
    @jwt_required()
    @api.expect(role_change_model)
    @api.doc(security='Bearer Auth', responses={200: 'Role updated successfully', 403: 'Unauthorized', 404: 'User not found'})
    @role_required(["Superuser"])
    def post(self):
        """Change the role of a user (Superuser only)"""
        user_id = request.json["user_id"]
        new_role = request.json["new_role"]
        
        if new_role not in ROLES:
            return {"error": "Invalid role"}, 400
        
        result = mongo.db.users.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"role": new_role, "approved": True}}
        )
        
        if result.modified_count:
            return {"message": "Role updated and user approved successfully"}, 200
        else:
            return {"error": "User not found"}, 404

@user_ns.route('/users')
class Users(Resource):
    @jwt_required()
    @api.doc(security='Bearer Auth', responses={200: 'Success', 403: 'Unauthorized'})
    @role_required(["Superuser"])
    def get(self):
        """Get all users (Superuser only)"""
        users = list(mongo.db.users.find({}, {"password": 0}))
        for user in users:
            user["_id"] = str(user["_id"])
        
        return users

@user_ns.route('/set_action_password')
class SetActionPassword(Resource):
    @jwt_required()
    @api.expect(action_password_model)
    @api.doc(security='Bearer Auth', responses={200: 'Action password set successfully', 403: 'Unauthorized'})
    @role_required(["Superuser"])
    def post(self):
        """Set the action password (Superuser only)"""
        current_user_id = get_jwt_identity()
        action_password = request.json["password"]
        
        hashed_action_password = bcrypt.generate_password_hash(action_password).decode("utf-8")
        mongo.db.users.update_one(
            {"_id": ObjectId(current_user_id)},
            {"$set": {"action_password": hashed_action_password}}
        )
        
        return {"message": "Action password set successfully"}, 200

@user_ns.route('/verify_action_password')
class VerifyActionPassword(Resource):
    @jwt_required()
    @api.expect(action_password_model)
    @api.doc(security='Bearer Auth', responses={200: 'Action password verified', 401: 'Invalid action password', 403: 'Unauthorized'})
    @role_required(["Superuser"])
    def post(self):
        """Verify the action password (Superuser only)"""
        current_user_id = get_jwt_identity()
        action_password = request.json["password"]
        
        user = mongo.db.users.find_one({"_id": ObjectId(current_user_id)})
        if bcrypt.check_password_hash(user.get("action_password", ""), action_password):
            return {"message": "Action password verified"}, 200
        else:
            return {"error": "Invalid action password"}, 401

@email_ns.route('/analyze')
class AnalyzeMail(Resource):
    @jwt_required()
    @api.doc(security='Bearer Auth', responses={200: 'Analysis successful', 400: 'No file provided', 403: 'Unauthorized'})
    @role_required(["Security Analyst", "Assistant Security Analyst", "Senior Security Analyst", "Security Analysis Supervisor", "Superuser"])
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