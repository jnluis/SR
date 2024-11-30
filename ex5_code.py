import os
import re
import sqlite3
import threading
from dataclasses import dataclass, field
from typing import List, Optional

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

def validate_input(input_str: str, filter_keywords: list) -> bool:
    input_lower = input_str.lower()
    
    pattern = r'\b(' + '|'.join(re.escape(keyword.lower()) for keyword in filter_keywords) + r')\b'
    
    match = re.search(pattern, input_lower)
    if match:
        print(f"Forbidden keyword detected: {match.group()}")
        return False
    
    return True

def vulnerable_login(username: str, password: str) -> list:
    filter_keywords = [
        "or", "and", "true", "false", "union", "like", 
        "=", ">", "<", ";", "--", "/*", "*/", "admin"
    ]
    
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
            password BLOB
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
                self.users[i] = user
                return user
        return None

    def create_user(self, username: str, password: str) -> Optional[UserProfile]:
        if self.get(username) is not None:
            return None
        user = UserProfile(username=username)
        user.password_hash = hash_pass(password, user.salt)
        self.users.append(user)
        print(f"Created user: {user}")
        return user

    def create_admin(self, username: str, password: str) -> Optional[UserProfile]:
        admin = self.create_user(username, password)
        if admin is None:
            return None
        admin.add_role("admin")
        print(f"Created admin user: {admin}")
        return admin

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
        cursor = self.conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}'"
        cursor.execute(query)
        user = cursor.fetchone()
        if user is not None:
            return UserProfile(username=user[0], password_hash=user[1], roles=user[2])
        return None
    
    def _db_create_user(self, username: str, password_hash: bytes, roles: list):
        try:
            cursor = self.conn.cursor()
            
# Estas insercoes funcionam pelo DB Browser
#     INSERT OR IGNORE INTO roles(name) VALUES ("admin");

# INSERT INTO users (username, password) VALUES ("bob", "opa");
# INSERT INTO user_roles(user_username, role_name) VALUES ("bob", "admin");
            user_query = "INSERT INTO users (username, password) VALUES (?, ?)"
            cursor.execute(user_query, (username, sqlite3.Binary(password_hash)))
            
            for role in roles:
                role_query = "INSERT OR IGNORE INTO roles (name) VALUES (?)"
                cursor.execute(role_query, role)
                
                user_roles_query = "INSERT INTO user_roles (user_username, role_name) VALUES (?, ?)"
                cursor.execute(user_roles_query, (username, role))
            
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
    
    def create_user(self, username: str, password: bytes, roles: list) -> Optional[UserProfile]:
        if self.get_user_by_username(username) is None:
            usr = UserProfile(username=username)
            usr.password_hash = hash_pass(password, usr.salt)
            self.lock.acquire()
            self.user_cache[username] = usr
            self.lock.release()
            self._db_create_user(username, usr.password_hash, roles)
            return usr
        return None

    def login_user(self, username: str, password: str) -> Optional[UserProfile]:
        user = self.get_user_by_username(username)
        if user is not None and verify_hash(password, user.salt, user.password_hash):
            return user
        return None


# Simulate the application
def main():

    # create_vulnerable_database()
    user_manager = UserManager()
    worker = Worker(threading.Lock(), user_manager, sqlite3.connect("vulnerable.db"))

    # Create normal users and admins
    alice = user_manager.create_user("alice", "password123")
    print(type(alice.password_hash))
    worker.create_user(alice.username, "password123", alice.roles)

    print(alice.roles)
    admin_bob = user_manager.create_admin("bob", "securepassword")
    worker.create_user(admin_bob.username, "password123", admin_bob.roles)
    print(admin_bob.roles)

    # Alice escalates privileges using shared mutable roles
    print(alice.roles)
    user_manager.login("alice", "password123")

    charlie = user_manager.create_user("charlie", "password123")
    worker.create_user(charlie.username, "password123", charlie.roles)

    print(user_manager.users)

        # Verify the DB content directly
    conn = sqlite3.connect("vulnerable.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    print("Users in DB:", cursor.fetchall())
    cursor.execute("SELECT * FROM roles")
    print("Roles in DB:", cursor.fetchall())
    cursor.execute("SELECT * FROM user_roles")
    print("User Roles in DB:", cursor.fetchall())
    conn.close()

if __name__ == "__main__":
    main()

    