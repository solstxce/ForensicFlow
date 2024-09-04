from pymongo import MongoClient
from flask_bcrypt import Bcrypt
import getpass

# Initialize Bcrypt
bcrypt = Bcrypt()

# MongoDB connection string
MONGO_URI = "mongodb://localhost:27017/forensicflow"

def add_superuser():
    # Connect to MongoDB
    client = MongoClient(MONGO_URI)
    db = client.get_database()
    users = db.users

    # Get superuser details
    username = input("Enter superuser username: ")
    password = getpass.getpass("Enter superuser password: ")
    
    # Hash the password
    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    
    # Create superuser document
    superuser = {
        "username": username,
        "password": hashed_password,
        "role": "Superuser",
        "approved": True
    }
    
    # Insert superuser into the database
    result = users.insert_one(superuser)
    
    if result.inserted_id:
        print(f"Superuser '{username}' added successfully with ID: {result.inserted_id}")
    else:
        print("Failed to add superuser")

    client.close()

if __name__ == "__main__":
    add_superuser()