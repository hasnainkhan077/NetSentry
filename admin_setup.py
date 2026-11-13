
import sqlite3
from getpass import getpass
from werkzeug.security import generate_password_hash

# Connect to the NetSentry database
connection = sqlite3.connect("netsentry.db")

# Create administrator table
connection.execute("""
    CREATE TABLE IF NOT EXISTS admin (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )
""")

# Check whether an administrator already exists
existing_admin = connection.execute(
    "SELECT id FROM admin"
).fetchone()

if existing_admin:
    print("An administrator account already exists.")
else:
    print("\n=== NetSentry Admin Setup ===")

    username = input("Create admin username: ").strip()

    password = getpass("Create admin password: ")
    confirm_password = getpass("Confirm admin password: ")

    if not username:
        print("Username cannot be empty.")

    elif len(password) < 12:
        print("Password must contain at least 12 characters.")

    elif password != confirm_password:
        print("Passwords do not match.")

    else:
        password_hash = generate_password_hash(password)

        connection.execute(
            "INSERT INTO admin (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )

        connection.commit()

        print("\nAdministrator account created successfully!")

connection.close()
