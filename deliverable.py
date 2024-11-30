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
                self.users[i] = user
                return user
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

        cursor = self.conn.cursor()

        query = f"""
            SELECT users.username
            FROM users
            WHERE users.username = '{username}' AND users.password = '{password}'
        """
        
        cursor.execute(query)
        result = cursor.fetchone()
        if result is not None:
            user = self.get_user_by_username(result[0])
            return user
        
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