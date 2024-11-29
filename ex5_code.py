import os
from dataclasses import dataclass, field
from typing import List, Optional
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidKey

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

@dataclass
class UserProfile:
    username: str
    password_hash: str = None
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

    def create_user(self, username: str, password: str) -> UserProfile:
        user = UserProfile(username=username)
        kdf = get_kdf(user.salt)
        user.password_hash = kdf.derive(password.encode())
        self.users.append(user)
        print(f"Created user: {user}")
        return user

    def create_admin(self, username: str, password: str) -> UserProfile:
        admin = self.create_user(username, password)
        admin.add_role("admin")
        print(f"Created admin user: {admin}")
        return admin

    def login(self, username: str, password: str) -> Optional[UserProfile]:
        for user in self.users:
            if user.username == username:
                kdf = get_kdf(user.salt)
                try:
                    kdf.verify(password.encode(), user.password_hash)
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
    user_manager.login("alice", "password123")


if __name__ == "__main__":
    main()

    