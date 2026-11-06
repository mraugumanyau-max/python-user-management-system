
# ==========================
# IMPORTS
# ==========================

import sqlite3
import hashlib
import secrets
import hmac
import json
import os

from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


# ==========================
# APPLICATION CONFIGURATION
# ==========================

# Get Railway's persistent storage directory
DATA_DIRECTORY = os.environ.get("RAILWAY_VOLUME_MOUNT_PATH", ".")

# Store the database inside that directory
FILE_NAME = os.path.join(DATA_DIRECTORY, "users.db")

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", 8000))


# ==========================
# DATABASE CONNECTION
# ==========================

def get_connection():
    connection = sqlite3.connect(FILE_NAME)

    # Allows us to access database columns by their names
    connection.row_factory = sqlite3.Row

    return connection


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

    # Convert salt and hash into hexadecimal
    salt = salt.hex()
    password_hash = password_hash.hex()

    # Return the complete password information
    return f"pbkdf2_sha256$600000${salt}${password_hash}"


# Verify whether an entered password is correct
def verify_password(password, stored_password):

    try:
        # Separate the stored password information
        algorithm, iterations, salt, stored_hash = stored_password.split("$")

        # Confirm the supported hashing algorithm
        if algorithm != "pbkdf2_sha256":
            return False

        # Convert the salt from hexadecimal into bytes
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
# CREATE USERS TABLE
# ==========================

def initialize_database():

    connection = get_connection()

    try:
        cursor = connection.cursor()

        # Create the users table if it does not exist
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
# JSON RESPONSE
# ==========================

def send_json_response(handler, status_code, data):

    # Convert Python dictionary into JSON bytes
    response = json.dumps(data).encode("utf-8")

    # Send HTTP status code
    handler.send_response(status_code)

    # Send response headers
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(response)))

    # Finish sending headers
    handler.end_headers()

    # Send JSON response body
    handler.wfile.write(response)


# ==========================
# READ JSON REQUEST
# ==========================

def read_json_request(handler):

    try:
        # Get the size of the incoming request body
        content_length = int(handler.headers.get("Content-Length", 0))

        if content_length <= 0:
            raise ValueError("Request body is empty.")

        # Read the request body
        body = handler.rfile.read(content_length)

        # Convert JSON data into a Python object
        data = json.loads(body.decode("utf-8"))

        # Ensure the JSON data is an object/dictionary
        if not isinstance(data, dict):
            raise ValueError("JSON data must be an object.")

        return data

    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f"Invalid request data: {error}")


# ==========================
# API REQUEST HANDLER
# ==========================

class APIHandler(BaseHTTPRequestHandler):

    # ==========================
    # HANDLE GET REQUESTS
    # ==========================

    def do_GET(self):

        # Parse the requested URL
        parsed_url = urlparse(self.path)

        # Welcome endpoint
        if parsed_url.path == "/":

            send_json_response(self, 200, {
                "message": "Welcome to User Management API"
            })

        # Search user endpoint
        elif parsed_url.path == "/search":

            connection = None

            try:
                # Extract username from URL query parameters
                query_parameters = parse_qs(parsed_url.query)

                username = query_parameters.get("username", [None])[0]

                # Validate username
                if not isinstance(username, str) or not username.strip():
                    raise ValueError("Please provide a username.")

                # Connect to database
                connection = get_connection()
                cursor = connection.cursor()

                # Search for user
                cursor.execute("""
                    SELECT id, name, username, age, registration_date
                    FROM users
                    WHERE username = ?
                """, (username.strip(),))

                user = cursor.fetchone()

                # Check whether user exists
                if user is None:
                    send_json_response(self, 404, {
                        "error": "User not found."
                    })

                else:
                    send_json_response(self, 200, {
                        "message": "User found successfully.",
                        "user": dict(user)
                    })

            except ValueError as error:
                send_json_response(self, 400, {
                    "error": str(error)
                })

            except sqlite3.Error:
                send_json_response(self, 500, {
                    "error": "A database error occurred."
                })

            finally:
                if connection is not None:
                    connection.close()

        else:
            send_json_response(self, 404, {
                "error": "Endpoint not found."
            })


    # ==========================
    # HANDLE POST REQUESTS
    # ==========================

    def do_POST(self):

        if self.path == "/register":

            connection = None

            try:
                # Read registration details from Postman
                data = read_json_request(self)

                # Extract user information
                name = data.get("name")
                username = data.get("username")
                password = data.get("password")
                confirm_password = data.get("confirm_password")
                age = data.get("age")

                # Validate required fields
                required_fields = [
                    name, username, password, confirm_password, age
                ]

                if any(value is None for value in required_fields):
                    raise ValueError("All fields are required.")

                # Validate text fields
                text_fields = [
                    name, username, password, confirm_password
                ]

                if not all(
                    isinstance(value, str) and value.strip()
                    for value in text_fields
                ):
                    raise ValueError(
                        "Text fields must contain valid text."
                    )

                # Validate password length
                if len(password) < 6:
                    raise ValueError(
                        "Password must contain at least 6 characters."
                    )

                # Confirm passwords match
                if password != confirm_password:
                    raise ValueError("Passwords do not match.")

                # Validate age
                if (
                    isinstance(age, bool)
                    or not isinstance(age, int)
                    or age <= 0
                ):
                    raise ValueError("Age must be a positive integer.")

                # Hash the password
                hashed_password = hash_password(password)

                # Generate registration date
                registration_date = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                # Connect to the database
                connection = get_connection()
                cursor = connection.cursor()

                # Insert user into the database
                cursor.execute("""
                    INSERT INTO users
                    (name, username, password, age, registration_date)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    name.strip(),
                    username.strip(),
                    hashed_password,
                    age,
                    registration_date
                ))

                # Save database changes
                connection.commit()

                # Send successful response
                send_json_response(self, 201, {
                    "message": "Registration successful!"
                })

            except ValueError as error:
                send_json_response(self, 400, {
                    "error": str(error)
                })

            except sqlite3.IntegrityError:
                send_json_response(self, 409, {
                    "error": "Username already exists."
                })

            except sqlite3.Error:
                send_json_response(self, 500, {
                    "error": "A database error occurred."
                })

            finally:
                if connection is not None:
                    connection.close()

        else:
            send_json_response(self, 404, {
                "error": "Endpoint not found."
            })


    # ==========================
    # HANDLE PUT REQUESTS
    # ==========================

    def do_PUT(self):

        if self.path == "/change-password":

            connection = None

            try:
                # Read data sent from Postman
                data = read_json_request(self)

                # Extract password information
                username = data.get("username")
                current_password = data.get("current_password")
                new_password = data.get("new_password")
                confirm_password = data.get("confirm_password")

                # Validate required fields
                if not all([
                    username,
                    current_password,
                    new_password,
                    confirm_password
                ]):
                    raise ValueError("All fields are required.")

                # Validate field types
                if not all(
                    isinstance(value, str) and value.strip()
                    for value in [
                        username,
                        current_password,
                        new_password,
                        confirm_password
                    ]
                ):
                    raise ValueError("All fields must contain valid text.")

                # Validate new password length
                if len(new_password) < 6:
                    raise ValueError(
                        "New password must contain at least 6 characters."
                    )

                # Confirm new passwords match
                if new_password != confirm_password:
                    raise ValueError("New passwords do not match.")

                # Connect to the database
                connection = get_connection()
                cursor = connection.cursor()

                # Find the user using their username
                cursor.execute(
                    "SELECT * FROM users WHERE username = ?",
                    (username.strip(),)
                )

                user = cursor.fetchone()

                # Check whether the user exists
                if user is None:
                    send_json_response(self, 404, {
                        "error": "User not found."
                    })
                    return

                # Verify the current password
                if not verify_password(current_password, user["password"]):
                    send_json_response(self, 401, {
                        "error": "Current password is incorrect."
                    })
                    return

                # Hash the new password before saving it
                hashed_password = hash_password(new_password)

                # Update the user's password in the database
                cursor.execute(
                    "UPDATE users SET password = ? WHERE username = ?",
                    (hashed_password, username.strip())
                )

                # Save changes to the database
                connection.commit()

                # Send success response
                send_json_response(self, 200, {
                    "message": "Password changed successfully!"
                })

            except ValueError as error:
                send_json_response(self, 400, {
                    "error": str(error)
                })

            except sqlite3.Error:
                send_json_response(self, 500, {
                    "error": "A database error occurred."
                })

            finally:
                if connection is not None:
                    connection.close()

        else:
            send_json_response(self, 404, {
                "error": "Endpoint not found."
            })


    # ==========================
    # HANDLE DELETE REQUESTS
    # ==========================

    def do_DELETE(self):

        if self.path == "/delete-account":

            connection = None

            try:
                # Read request data from Postman
                data = read_json_request(self)

                username = data.get("username")
                password = data.get("password")

                # Validate required fields
                if not username or not password:
                    raise ValueError(
                        "Username and password are required."
                    )

                if not isinstance(username, str) or not username.strip():
                    raise ValueError("Invalid username.")

                if not isinstance(password, str) or not password:
                    raise ValueError("Invalid password.")

                # Connect to database
                connection = get_connection()
                cursor = connection.cursor()

                # Find user
                cursor.execute(
                    "SELECT * FROM users WHERE username = ?",
                    (username.strip(),)
                )

                user = cursor.fetchone()

                # Check whether the user exists
                if user is None:
                    send_json_response(self, 404, {
                        "error": "User not found."
                    })
                    return

                # Verify password
                if not verify_password(password, user["password"]):
                    send_json_response(self, 401, {
                        "error": "Incorrect password."
                    })
                    return

                # Delete user
                cursor.execute(
                    "DELETE FROM users WHERE id = ?",
                    (user["id"],)
                )

                connection.commit()

                # Send success response
                send_json_response(self, 200, {
                    "message": "Account deleted successfully."
                })

            except ValueError as error:
                send_json_response(self, 400, {
                    "error": str(error)
                })

            except sqlite3.Error:
                send_json_response(self, 500, {
                    "error": "A database error occurred."
                })

            finally:
                if connection is not None:
                    connection.close()

        else:
            send_json_response(self, 404, {
                "error": "Endpoint not found."
            })


# ==========================
# START THE API SERVER
# ==========================

if __name__ == "__main__":

    try:
        # Create the database and users table
        initialize_database()

        # Create the HTTP server
        server = HTTPServer((HOST, PORT), APIHandler)

        print("User Management API is running")
        print(f"Server running at http://{HOST}:{PORT}")
        print("Press CTRL + C to stop the server.")

        # Keep the server running
        server.serve_forever()

    except KeyboardInterrupt:
        print("\nServer stopped successfully.")

    except OSError as error:
        print(f"Server startup error: {error}")

    finally:
        if "server" in locals():
            server.server_close()
