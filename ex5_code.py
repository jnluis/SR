from flask import Flask, request, jsonify, session
import hashlib
import sqlite3

app = Flask(__name__)
app.secret_key = 'easily_guessable_secret'  # Vulnerability: Weak secret key

def vulnerable_authenticate(username, password):
    """
    Demonstrates multiple authentication security vulnerabilities
    """
    # Vulnerability 1: Weak password hashing
    # Uses simple MD5 which is cryptographically broken
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    
    # Vulnerability 2: SQL Injection risk
    # Directly interpolating user input into SQL query
    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # EXTREMELY DANGEROUS SQL INJECTION VULNERABILITY
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed_password}'"
        cursor.execute(query)
        
        user = cursor.fetchone()
        
        if user:
            # Vulnerability 3: Weak session management
            session['user'] = username
            session['authenticated'] = True
            
            return jsonify({
                'status': 'success',
                'message': f'Logged in as {username}',
                # Vulnerability 4: Exposing sensitive user information
                'user_details': {
                    'username': username,
                    'user_id': user[0],
                    'email': user[2]
                }
            }), 200
        else:
            return jsonify({'status': 'failed', 'message': 'Invalid credentials'}), 401
    
    except sqlite3.Error as e:
        # Vulnerability 5: Detailed error messages that could aid attackers
        return jsonify({
            'status': 'error', 
            'message': f'Database error: {str(e)}'
        }), 500
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    # Vulnerability 6: No rate limiting or brute force protection
    username = request.json.get('username', '')
    password = request.json.get('password', '')
    
    return vulnerable_authenticate(username, password)

###################################################################################################################
def access_object(obj, attr):
    return getattr(obj, attr)  # Looks fine but allows arbitrary attribute access

class MyClass:
    def __init__(self):
        self.secret = "Top Secret"

instance = MyClass()
print(access_object(instance, "__dict__"))  # Exposes all internal data

class RemoteShell:
    def __reduce__(self):
        import os
        return (os.system, ("echo 'Hacked!'",))

def load_and_execute(serialized_data):
    data = pickle.loads(serialized_data)
    print("Data Loaded:", data)

# Simulating deserialization vulnerability via pickled object
malicious_object = pickle.dumps(RemoteShell())

# Hidden vulnerability: The code executed when the object is deserialized
load_and_execute(malicious_object)  # Will execute os.system('echo "Hacked!"')

def sensitive_action(user_input):
    if "admin" in user_input:
        print("Admin access granted!")
        return True
    return False

def perform_action(input_data):
    if sensitive_action(input_data):
        print("Performing privileged action...")
        # executar aqui com o input data
    else:
        print("Insufficient permissions")

# Subtle exploit that occurs under a specific sequence of actions
perform_action("admin; system('echo hacked')")  # Dangerous shell injection

# USAR O NOME DA VARIÁVEL ALGURES PARA ENGANAR
len = lambda x: "Hello, World!"
print(len([1, 2, 3]))  # Prints "Hello, World!"