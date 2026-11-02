# ==========================
# IMPORTS
# ==========================

import sqlite3
import hashlib
import secrets
import hmac
from datetime import datetime

# Name of the CSV file where user details are stored
FILE_NAME = "users.users.db"


# ==========================
# MAIN MENU
# ==========================

def main():
    print("\n================================")
    print("      USER MANAGEMENT SYSTEM")
    print("================================")
    print("1. Register")
    print("2. Login")
    print("3. Search User")
    print("4. Exit")
    print("================================")


# ==========================
# PASSWORD SECURITY
# ==========================

# Hash a password before storing it in the database
def hash_password(password):

    # Generate a random 16-byte salt
    salt = secrets.token_bytes(16)

    # Hash the password using PBKDF2 with SHA-256
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600000
    )

    # Convert the salt and password hash into hexadecimal
    salt = salt.hex()
    password_hash = password_hash.hex()

    # Return the complete password information as a string
    return f"pbkdf2_sha256$600000${salt}${password_hash}"


# Verify whether the password entered during login is correct
def verify_password(password, stored_password):

    try:
        # Separate the stored password information
        algorithm, iterations, salt, stored_hash = stored_password.split("$")

        # Confirm that the supported hashing algorithm was used
        if algorithm != "pbkdf2_sha256":
            return False

        # Convert the stored salt from hexadecimal into bytes
        salt = bytes.fromhex(salt)

        # Hash the password entered by the user
        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            int(iterations)
        ).hex()

        # Compare both hashes securely
        return hmac.compare_digest(new_hash, stored_hash)

    except (ValueError, TypeError, AttributeError):
        return False

# ==========================
# DATABASE CONNECTION
# ==========================

DATABASE_NAME = "users.db"


def get_connection():

    connection = sqlite3.connect(DATABASE_NAME)

    # Allow access to columns using their names
    connection.row_factory = sqlite3.Row

    return connection


# ==========================
# CREATE USERS TABLE
# ==========================

def initialize_database():

    connection = get_connection()

    try:
        cursor = connection.cursor()

        # Create the users table if it does not already exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password TEXT NOT NULL,
                age INTEGER NOT NULL,
                registration_date TEXT NOT NULL
            )
        """)

        connection.commit()

        print("Database initialized successfully!")

    except sqlite3.Error as error:
        print(f"Database initialization error: {error}")

    finally:
        connection.close()
# ==========================
# USER REGISTRATION
# ==========================

def register():

    print("\n--- USER REGISTRATION ---")

    try:
        # Collect user details
        name = input("Enter your full name: ").strip()
        username = input("Enter your username: ").strip()
        password = input("Enter your password: ")
        confirm_password = input("Confirm your password: ")
        age_input = input("Enter your age: ").strip()

        # Check that no field is empty
        if not all([name, username, password, confirm_password, age_input]):
            raise ValueError("No field should be empty.")

        # Check password length
        if len(password) < 6:
            raise ValueError("Password must have at least 6 characters.")

        # Check password confirmation
        if password != confirm_password:
            raise ValueError("Passwords do not match.")

        # Convert age into an integer
        try:
            age = int(age_input)
        except ValueError:
            raise ValueError("Age must be a positive integer.")

        # Check that age is positive
        if age <= 0:
            raise ValueError("Age must be a positive integer.")

        # Capture registration date and time
        registration_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Hash the password before saving it
        hashed_password = hash_password(password)

        # Connect to the database
        connection = get_connection()

        try:
            cursor = connection.cursor()

            # Insert the new user into the SQL database
            cursor.execute("""
                INSERT INTO users
                (name, username, password, age, registration_date)
                VALUES (?, ?, ?, ?, ?)
            """, (
                name,
                username,
                hashed_password,
                age,
                registration_date
            ))

            # Save changes to the database
            connection.commit()

        finally:
            connection.close()

        print("Registration successful!")

    except sqlite3.IntegrityError:
        print("Registration error: Username already exists.")

    except ValueError as error:
        print(f"Registration error: {error}")

    except sqlite3.Error as error:
        print(f"Database error: {error}")

# ==========================
# USER LOGIN
# ==========================


# ==========================
# USER LOGIN
# ==========================

def login():

    print("\n===== USER LOGIN =====")

    attempts = 0
    max_attempts = 3

    while attempts < max_attempts:

        # Collect login details
        username = input("Enter your username: ").strip()
        password = input("Enter your password: ")

        try:
            # Connect to the database
            connection = get_connection()

            try:
                cursor = connection.cursor()

                # Search for the user using their username
                cursor.execute("""
                    SELECT * FROM users
                    WHERE username = ?
                """, (username,))

                user_row = cursor.fetchone()

            finally:
                connection.close()

            # Check whether the username exists
            if user_row is None:
                raise ValueError("Invalid username or password.")

            # Convert SQLite row into a normal Python dictionary
            user = dict(user_row)

            # Verify the entered password against the stored hash
            if not verify_password(password, user["password"]):
                raise ValueError("Invalid username or password.")

            # Login successful
            print("\nLogin successful!")

            # Open the user dashboard
            dashboard(user)

            return

        except ValueError as error:

            attempts += 1

            print(f"Login error: {error}")

            remaining = max_attempts - attempts

            if remaining > 0:
                print(f"You have {remaining} attempt(s) remaining.")

            else:
                print("Maximum login attempts reached!")
                print("Returning to the main menu.")

        except sqlite3.Error as error:

            print(f"Database error: {error}")
            return



# ==========================
# CHANGE USER PASSWORD
# ==========================

def change_password(user):

    print("\n===== CHANGE PASSWORD =====")

    try:
        # Ask for the current password
        current_password = input("Enter your current password: ")

        # Verify the current password
        if not verify_password(current_password, user["password"]):
            raise ValueError("Incorrect current password.")

        # Ask for the new password
        new_password = input("Enter your new password: ")
        confirm_password = input("Confirm your new password: ")

        # Check that password fields are not empty
        if not new_password or not confirm_password:
            raise ValueError("Password fields cannot be empty.")

        # Check password length
        if len(new_password) < 6:
            raise ValueError("Password must have at least 6 characters.")

        # Check password confirmation
        if new_password != confirm_password:
            raise ValueError("New passwords do not match.")

        # Hash the new password
        hashed_password = hash_password(new_password)

        # Connect to the SQLite database
        connection = get_connection()

        try:
            cursor = connection.cursor()

            # Update the password for the logged-in user
            cursor.execute("""
                UPDATE users
                SET password = ?
                WHERE id = ?
            """, (hashed_password, user["id"]))

            # Check whether a user record was updated
            if cursor.rowcount == 0:
                raise ValueError("User account could not be found.")

            # Save changes to the database
            connection.commit()

        finally:
            connection.close()

        # Update the user's password in memory
        user["password"] = hashed_password

        print("Password changed successfully!")

    except ValueError as error:
        print(f"Password error: {error}")

    except sqlite3.Error as error:
        print(f"Database error: {error}")



# ==========================
# DELETE USER ACCOUNT
# ==========================

def delete_account(user):

    print("\n--- DELETE ACCOUNT ---")

    try:
        # Ask for the user's password
        password = input("Enter your password to confirm deletion: ")

        # Verify the password
        if not verify_password(password, user["password"]):
            raise ValueError(
                "Incorrect password. Account deletion cancelled."
            )

        # Ask for confirmation
        confirmation = input(
            "Are you sure you want to delete your account? (yes/no): "
        ).strip().lower()

        if confirmation != "yes":
            print("Account deletion cancelled.")
            return False

        # Connect to the SQLite database
        connection = get_connection()

        try:
            cursor = connection.cursor()

            # Delete only the currently logged-in user's account
            cursor.execute("""
                DELETE FROM users
                WHERE id = ?
            """, (user["id"],))

            # Check whether a user was deleted
            if cursor.rowcount == 0:
                raise ValueError("User account could not be found.")

            # Save the deletion
            connection.commit()

        finally:
            connection.close()

        print("Your account has been deleted successfully!")

        return True

    except ValueError as error:
        print(f"Deletion error: {error}")

    except sqlite3.Error as error:
        print(f"Database error: {error}")

    return False




# ==========================
# SEARCH USER BY USERNAME
# ==========================

def search_user():

    print("\n===== SEARCH USER =====")

    try:
        # Ask for the username to search
        search_username = input("Enter username to search: ").strip()

        # Check that the username is not empty
        if not search_username:
            raise ValueError("Username cannot be empty.")

        # Connect to the SQLite database
        connection = get_connection()

        try:
            cursor = connection.cursor()

            # Search for the user in the database
            cursor.execute("""
                SELECT name, username
                FROM users
                WHERE username = ?
            """, (search_username,))

            # Retrieve the matching user
            user = cursor.fetchone()

        finally:
            connection.close()

        # Check whether the user exists
        if user:

            print("\nUser found!")
            print("--------------------------")
            print(f"Full Name: {user['name']}")
            print(f"Username: {user['username']}")
            print("--------------------------")

        else:
            print("User not found.")

    except ValueError as error:
        print(f"Search error: {error}")

    except sqlite3.Error as error:
        print(f"Database error: {error}")


# ==========================
# USER DASHBOARD
# ==========================

def dashboard(user):

    while True:

        print("\n===== USER DASHBOARD =====")
        print("1. View Profile")
        print("2. Change Password")
        print("3. Logout")
        print("4. Delete Account")
        print("==========================")

        choice = input("Enter your choice: ").strip()

        # ==========================
        # VIEW USER PROFILE
        # ==========================

        if choice == "1":

            print("\n===== USER PROFILE =====")

            print(f"User ID: {user['id']}")
            print(f"Full Name: {user['name']}")
            print(f"Username: {user['username']}")
            print(f"Age: {user['age']}")

            print(
                f"Registration Date: "
                f"{user['registration_date']}"
            )

            print("========================")

        # ==========================
        # CHANGE PASSWORD
        # ==========================

        elif choice == "2":

            change_password(user)

        # ==========================
        # LOGOUT
        # ==========================

        elif choice == "3":

            print("You have logged out successfully.")
            break

        # ==========================
        # DELETE ACCOUNT
        # ==========================

        elif choice == "4":

            deleted = delete_account(user)

            if deleted:
                break

        # ==========================
        # INVALID CHOICE
        # ==========================

        else:

            print("Invalid choice. Please select 1, 2, 3, or 4.")


            
# ==========================
# MAIN PROGRAM
# ==========================

initialize_database()

while True:
    main()

    choice = input("Enter a choice: ").strip()

    if choice == "1":
        register()

    elif choice == "2":
        login()

    elif choice == "3":
        search_user()

    elif choice == "4":
        print("Goodbye!")
        break

    else:
        print("Invalid choice. Please select 1, 2, 3 or 4.")
