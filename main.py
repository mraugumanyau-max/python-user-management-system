#imports
import csv
import os
from datetime import datetime
import hashlib
import secrets
import hmac

# Name of the CSV file where user details are stored
FILE_NAME = "users.csv"


# ==========================
# MAIN MENU
# ==========================
def main():
    print("\n================================")
    print("    USER MANAGEMENT SYSTEM")
    print("================================")
    print("1. Register")
    print("2. Login")
    print("3. Search User")
    print("4. Exit")
    print("================================")

#hash the passwords for security
def hash_password(password):
    # Generate a random salt
    salt = secrets.token_bytes(16)

    # Hash the password using PBKDF2
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600000
    )

    # Convert salt and hash into hexadecimal strings
    salt = salt.hex()
    password_hash = password_hash.hex()

    # Return the complete hashed password
    return f"pbkdf2_sha256$600000${salt}${password_hash}"


#checks whether a password entered during login is correct.
def verify_password(password, stored_password):

    try:
        # Separate the stored password information
        algorithm, iterations, salt, stored_hash = stored_password.split("$")

        # Check the hashing algorithm
        if algorithm != "pbkdf2_sha256":
            return False

        # Convert the stored salt into bytes
        salt = bytes.fromhex(salt)

        # Hash the password entered during login
        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            int(iterations)
        ).hex()

        # Compare the newly generated hash with the stored hash
        return hmac.compare_digest(new_hash, stored_hash)

    except (ValueError, TypeError, AttributeError):
        return False
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

        # Check whether the username already exists
        if os.path.exists(FILE_NAME):
            with open(FILE_NAME, "r", newline="") as file:
                reader = csv.DictReader(file)

                for user in reader:
                    if user["username"].lower() == username.lower():
                        raise ValueError("Username already exists.")

        # Check password length
        if len(password) < 6:
            raise ValueError("Password must have at least 6 characters.")

        # Check password confirmation
        if password != confirm_password:
            raise ValueError("Passwords do not match.")

        # Convert age to an integer
        try:
            age = int(age_input)
        except ValueError:
            raise ValueError("Age must be a positive integer.")

        # Check that age is positive
        if age <= 0:
            raise ValueError("Age must be a positive integer.")

        # Capture registration date and time
        registration_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Check whether the file exists
        file_exists = os.path.exists(FILE_NAME)

        # Open CSV file
        with open(FILE_NAME, "a", newline="") as file:

            # Define CSV columns
            fieldnames = [
                "name",
                "username",
                "password",
                "age",
                "registration_date"
            ]

            # Create CSV writer
            writer = csv.DictWriter(file, fieldnames=fieldnames)

            # Add headings if the file is new or empty
            if not file_exists or os.path.getsize(FILE_NAME) == 0:
                writer.writeheader()

            # Hash the password before saving it
            hashed_password = hash_password(password)

            # Save the user's details1
            writer.writerow({
                "name": name,
                "username": username,
                "password": hashed_password,
                "age": age,
                "registration_date": registration_date
            })

        print("Registration successful!")

    except ValueError as error:
        print(f"Registration error: {error}")

    except (OSError, csv.Error) as error:
        print(f"File error: {error}")


# ==========================
# USER LOGIN
# ==========================


def login():
    print("\n===== USER LOGIN =====")

    attempts = 0
    max_attempts = 3

    while attempts < max_attempts:
        username = input("Enter your username: ").strip()
        password = input("Enter your password: ")

        try:
            with open(FILE_NAME, "r", newline="") as file:
                reader = csv.DictReader(file)

                for user in reader:
                    if (
                        user["username"].lower() == username.lower()
                        and verify_password(password, user["password"])
                    ):
                        print("Login successful!")
                        dashboard(user)
                        return

                # Raise an exception if details are incorrect
                raise ValueError("Incorrect username or password.")

        except FileNotFoundError:
            print("No registered users found. Please register first.")
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

        except (OSError, csv.Error) as error:
            print(f"File error: {error}")
            return

# ==========================
# CHANGE USER ACCOUNT
# ==========================

def change_password(user):
    print("\n===== CHANGE PASSWORD =====")

    try:
        # Ask for the current password
        current_password = input("Enter your current password: ")

        # Verify the current password using password hashing
        if not verify_password(current_password, user["password"]):
            raise ValueError("Incorrect current password.")

        # Ask for the new password
        new_password = input("Enter your new password: ")
        confirm_password = input("Confirm your new password: ")

        # Check that fields are not empty
        if not new_password or not confirm_password:
            raise ValueError("Password fields cannot be empty.")

        # Check password length
        if len(new_password) < 6:
            raise ValueError("Password must have at least 6 characters.")

        # Check password confirmation
        if new_password != confirm_password:
            raise ValueError("New passwords do not match.")

        # Hash the new password before saving it
        hashed_password = hash_password(new_password)

        # Read all users from the CSV file
        with open(FILE_NAME, "r", newline="") as file:
            reader = csv.DictReader(file)
            users = list(reader)

        # Track whether the current user was found
        user_found = False

        # Update only the matching user's password
        for registered_user in users:
            if registered_user["username"].lower() == user["username"].lower():
                registered_user["password"] = hashed_password
                user_found = True
                break

        if not user_found:
            raise ValueError("User account could not be found.")

        # Save all user records back to the CSV file
        with open(FILE_NAME, "w", newline="") as file:

            # Include all five CSV columns
            fieldnames = [
                "name",
                "username",
                "password",
                "age",
                "registration_date"
            ]

            writer = csv.DictWriter(file, fieldnames=fieldnames)

            writer.writeheader()
            writer.writerows(users)

        # Update the current user's password in memory
        user["password"] = hashed_password

        print("Password changed successfully!")

    except ValueError as error:
        print(f"Password error: {error}")

    except (OSError, csv.Error) as error:
        print(f"File error: {error}")


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
            raise ValueError("Incorrect password. Account deletion cancelled.")

        # Ask for confirmation
        confirmation = input(
            "Are you sure you want to delete your account? (yes/no): "
        ).strip().lower()

        if confirmation != "yes":
            print("Account deletion cancelled.")
            return

        # Read all existing users
        with open(FILE_NAME, "r", newline="") as file:
            reader = csv.DictReader(file)
            users = list(reader)

        # Keep every user except the currently logged-in user
        remaining_users = [
            existing_user
            for existing_user in users
            if existing_user["username"].lower() != user["username"].lower()
        ]

        # Check whether the user was actually found
        if len(remaining_users) == len(users):
            raise ValueError("User account could not be found.")

        # Rewrite the CSV file with the remaining users
        with open(FILE_NAME, "w", newline="") as file:

            fieldnames = [
                "name",
                "username",
                "password",
                "age",
                "registration_date"
            ]

            writer = csv.DictWriter(file, fieldnames=fieldnames)

            writer.writeheader()
            writer.writerows(remaining_users)

        print("Your account has been deleted successfully!")

        return True

    except ValueError as error:
        print(f"Deletion error: {error}")

    except (OSError, csv.Error) as error:
        print(f"File error: {error}")


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

        # Open the CSV file and read registered users
        with open(FILE_NAME, "r", newline="") as file:
            reader = csv.DictReader(file)

            # Search through all registered users
            for user in reader:

                # Compare usernames without considering uppercase/lowercase
                if user["username"].lower() == search_username.lower():

                    print("\nUser found!")
                    print("--------------------------")
                    print(f"Full Name: {user['name']}")
                    print(f"Username: {user['username']}")
                    print("--------------------------")

                    return

        # Display this message if no matching user exists
        print("User not found.")

    except ValueError as error:
        print(f"Search error: {error}")

    except (OSError, csv.Error) as error:
        print(f"File error: {error}")

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

        if choice == "1":
            print("\n===== USER PROFILE =====")
            print(f"Full Name: {user['name']}")
            print(f"Username: {user['username']}")
            print(f"Age: {user['age']}")
            print(f"Registration Date: {user.get('registration_date', 'Not available')}")
            print("========================")

        elif choice == "2":
            change_password(user)

        elif choice == "3":
            print("You have logged out successfully.")
            break

        elif choice == "4":
            deleted = delete_account(user)

            if deleted:
                break

        else:
            print("Invalid choice. Please select 1, 2, 3, or 4.")


# ==========================
# MAIN PROGRAM
# ==========================
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
