import hashlib
import sqlite3

# Database setup
conn = sqlite3.connect('users.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS users
                  (username TEXT, password TEXT, role TEXT)''')
conn.commit()

def authenticate(username, password):
    """Authenticate user by username and password."""
    # Vulnerability 1: SQL Injection
    query = f"SELECT password FROM users WHERE username='{username}'"
    cursor.execute(query)
    stored_password = cursor.fetchone()
    
    if stored_password:
        # Vulnerability 2: Weak Hashing (MD5)
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        return stored_password[0] == hashed_password
    return False

def authorize(username, role_required):
    """Authorize user by checking their role."""
    cursor.execute("SELECT role FROM users WHERE username=?", (username,))
    user_role = cursor.fetchone()
    return user_role and user_role[0] == role_required

def login(username, password, role_required):
    """Process user login and authorization."""
    if authenticate(username, password):
        print("Authentication successful")
        if authorize(username, role_required):
            print(f"Authorization successful: Welcome {role_required}!")
        else:
            print("Authorization failed: Access denied")
    else:
        print("Authentication failed: Invalid username or password")

# Example usage
login("admin", "password123", "admin")

# Close the database connection
conn.close()
