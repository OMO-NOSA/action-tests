import sqlite3
from flask import Flask, request, jsonify
import hashlib

app = Flask(__name__)

# Vulnerable database connection
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# Vulnerable user authentication
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Vulnerability 1: SQL Injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    
    if user:
        # Vulnerability 2: Weak password hashing
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        
        # Vulnerability 3: Sensitive information exposure
        return jsonify({"status": "success", "user_id": user[0], "admin": user[3]})
    else:
        return jsonify({"status": "failure", "message": "Invalid credentials"})

# Vulnerable user authorization
@app.route('/admin', methods=['GET'])
def admin_panel():
    user_id = request.args.get('user_id')
    
    # Vulnerability 4: Insecure direct object reference
    query = f"SELECT is_admin FROM users WHERE id = {user_id}"
    cursor.execute(query)
    is_admin = cursor.fetchone()[0]
    
    if is_admin:
        # Vulnerability 5: Command injection
        command = request.args.get('command', '')
        import os
        output = os.popen(command).read()
        return jsonify({"status": "success", "output": output})
    else:
        return jsonify({"status": "failure", "message": "Unauthorized access"})

# Vulnerability 6: Insecure password reset
@app.route('/reset_password', methods=['POST'])
def reset_password():
    email = request.form['email']
    new_password = request.form['new_password']
    
    # Vulnerability 7: Weak password policy
    if len(new_password) >= 6:
        # Update password logic here
        return jsonify({"status": "success", "message": "Password updated"})
    else:
        return jsonify({"status": "failure", "message": "Password too short"})

if __name__ == '__main__':
    app.run(debug=True)  # Vulnerability 8: Debug mode enabled in production