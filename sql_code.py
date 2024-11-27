def validate_query(user_input: str, filter_list: list) -> bool:
    # Normalize input for case-insensitive comparison
    user_input_lower = user_input.lower()

    for keyword in filter_list:
        if keyword.lower() in user_input_lower:
            print(f"Input rejected: Contains forbidden keyword '{keyword}'")
            return False
    return True

def execute_unsafe_query(query: str) -> list:
    """
    Execute a raw SQL query against a MySQL database unsafely (not recommended).

    Args:
        query (str): The SQL query to execute directly as a string.

    Returns:
        list: Results from the database query.
    """
    try:
        # Establish a connection to the MySQL database
        connection = mysql.connector.connect(
            host="localhost",      # Replace with your database host
            user="root",           # Replace with your database username
            password="password",   # Replace with your database password
            database="test_db"     # Replace with your database name
        )

        if connection.is_connected():
            cursor = connection.cursor()
            cursor.execute(query)  # Directly executes the raw query
            
            validate_query(query)
            # For SELECT queries, fetch results
            if query.strip().lower().startswith("select"):
                results = cursor.fetchall()
                return results
            
            # For INSERT/UPDATE/DELETE, commit changes
            connection.commit()
            return []

    except Error as e:
        print(f"Error: {e}")
        return []
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Example usage:
if __name__ == "__main__":
    filter_keywords = [
        "or", "and", "true", "false", "union", "like", "=", ">", "<", 
        ";", "--", "/*", "*/", "admin"
    ]

    # Example inputs
    inputs = [
        "SELECT * FROM users WHERE username = 'admin';",
        "DROP TABLE users --",
        "safe_input",
        "username LIKE 'alice'"
    ]

    for user_input in inputs:
        print(f"Validating: {user_input}")
        is_safe = validate_query(user_input, filter_keywords)
        print("Safe Input!" if is_safe else "Unsafe Input!", "\n")
