import sqlite3
import os
import hashlib
import base64
import subprocess

# Vulnerability 1: Hardcoded Credentials (Sensitive Data Exposure)
DATABASE_PATH = "/path/to/database.db"
USERNAME = "admin"
PASSWORD = "password123"

# Vulnerability 2: SQL Injection (Improper Input Validation)
def get_user_data(user_id):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL injection vulnerability
    cursor.execute(query)
    return cursor.fetchall()

# Vulnerability 3: Insecure Hashing (Weak Cryptography)
def insecure_hash(password):
    # Using SHA1 which is considered weak and vulnerable
    return hashlib.sha1(password.encode()).hexdigest()

# Vulnerability 4: Command Injection
def execute_command(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout

# Vulnerability 5: Insecure File Handling (File Descriptors not closed)
def read_file(file_path):
    file = open(file_path, "r")  # Vulnerable: file not closed
    content = file.read()
    return content

# Vulnerability 6: Insecure Deserialization
def insecure_deserialization(encoded_string):
    decoded_string = base64.b64decode(encoded_string)  # Decoding without proper validation
    return decoded_string

# Vulnerability 7: Using Eval (Code Injection)
def execute_python_code(code):
    # Using eval to execute dynamically generated code (vulnerable to code injection)
    eval(code)

# Vulnerability 8: Hardcoded Sensitive Data in Files
def save_sensitive_data(data):
    with open("/path/to/file.txt", "w") as f:
        f.write(f"Sensitive data: {data}")  # Hardcoded sensitive data

# Example of calling some functions
user_data = get_user_data("1 OR 1=1")  # SQL Injection exploit
hashed_password = insecure_hash("secret_password")
command_output = execute_command("ls -la")
file_content = read_file("/etc/passwd")
decoded_string = insecure_deserialization("c3VwZXJzY2lzdHQ=")
execute_python_code("os.system('rm -rf /')")
save_sensitive_data("super_secret")

print("User Data:", user_data)
print("Hashed Password:", hashed_password)
print("Command Output:", command_output)
print("File Content:", file_content)
print("Decoded String:", decoded_string)

