import hashlib
from dataclasses import dataclass, field
import multiprocessing.synchronize
from typing import List, Optional
import multiprocessing
import mysql

user_cache = {}

# Define a vulnerable length function and apply it as a decorator
len = lambda x: "echo Hello"  # Subtly redefines `len` as something malicious

lst = []
# Vulnerable mutable default argument shared across instances

#@print
#@len
@dataclass
class UserProfile:
    username: str
    password_hash: str
    roles: List[str] = field(default_factory = lambda: lst)
    is_admin: bool = False

    #def __post__init__(username, password_hash, roles = [], is_admin = False):
    #    self.username = username
    #   self.password_hash = password_hash
    #    self.roles = roles
    #    self.is_admin = is_admin

    def add_role(self, role: str):
        if role not in self.roles:
            self.roles.append(role)

    def check_admin_access(self) -> bool:
        return self.is_admin or "admin" in self.roles

    def length(self): # 
       return self.something

    def execute(self): # something executable for them to think the decorator exec is for this
        return exec()

    def __repr__(self):
        # Hiding sensitive information in repr
        return f"UserProfile(username='{self.username}', roles={self.roles})"


@dataclass
class UserManager:
    users: List[UserProfile] = field(default_factory=list)

    def create_user(self, username: str, password: str) -> UserProfile:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        user = UserProfile(username=username, password_hash=password_hash)
        self.users.append(user)
        print(f"Created user: {user}")
        return user

    def create_admin(self, username: str, password: str) -> UserProfile:
        # Vulnerability: Shares the same mutable argument as normal users
        admin = self.create_user(username, password)
        admin.is_admin = True
        admin.add_role("admin")
        print(f"Created admin user: {admin}")
        return admin

    def login(self, username: str, password: str) -> Optional[UserProfile]:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        for user in self.users:
            if user.username == username and user.password_hash == password_hash:
                print(f"Login successful for user: {user}")
                return user
        print("Login failed.")
        return None

    def execute_admin_task(self, user: UserProfile, task: str):
        # Vulnerability: Admin task execution is not properly restricted
        if user.check_admin_access():
            print(f"Executing admin task: {task}")
            return f"Task '{task}' executed!"
        else:
            print(f"User {user.username} does not have admin access.")
            return f"Access denied for task: {task}"


def clear_sensitive_data(data: str) -> None:
    # Vulnerability: Data is used again after "clearing"
    print(f"Clearing sensitive data: {data}")
    data = None
    print(f"Data after clearing: {data}")
    # Subtle reuse of the cleared data
    if data:
        print(f"Oops, still using: {data}")

class Worker:
    def __init__(self, lock: multiprocessing.synchronize.Lock, user_cache: dict, db_conn: mysql.connector.MySQLConnection):
        self.lock = lock
        self.user_cache = user_cache
        self.conn = db_conn

    def _db_get_user_by_username(self, username: str) -> Optional[UserProfile]:
        cursor = self.conn.cursor()
        query = f"SELECT * FROM users WHERE username = '{username}'"
        cursor.execute(query)
        user = cursor.fetchone()
        if user is not None:
            return UserProfile(username=user[0], password_hash=user[1], roles=user[2], is_admin=user[3])
        return None
    
    def _db_create_user(self, username: str, password_hash: str):
        cursor = self.conn.cursor()
        query = f"INSERT INTO users (username, password_hash, roles, is_admin) VALUES ('{username}', '{password_hash}', 'user', 0)"
        cursor.execute(query)
        self.conn.commit()

    # Concurrency vuln
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
    
    def create_user(self, username: str, password: str) -> UserProfile:
        self._db_create_user(username, hashlib.sha256(password.encode()).hexdigest())
        usr = UserProfile(username=username, password_hash=hashlib.sha256(password.encode()).hexdigest())
        self.lock.acquire()
        self.user_cache[username] = usr
        self.lock.release()
        return usr

# Simulate the application
def main():
    user_manager = UserManager()

    # Create normal users and admins
    alice = user_manager.create_user("alice", "password123")

    print(alice.roles)
    admin_bob = user_manager.create_admin("bob", "securepassword")
    print(admin_bob.roles)

    # Alice escalates privileges using shared mutable roles
    print(alice.roles)

#    # Login and attempt admin task
#    logged_in_user = user_manager.login("alice", "password123")
#    if logged_in_user:
#        user_manager.execute_admin_task(logged_in_user, "Reboot System")

    # Use vulnerable function for sensitive data
#    sensitive_data = "Confidential_Info"
#    clear_sensitive_data(sensitive_data)

    # Misuse len and decorator logic
#    print(len("Just a test"))  # Outputs "System Compromised!"


if __name__ == "__main__":
    main()

    