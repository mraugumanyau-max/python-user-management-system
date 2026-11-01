# USER MANAGEMENT SYSTEM

## 1. About the Program

The User Management System is a simple Python program that helps people create and manage user accounts.

It allows users to register, log in, change their passwords and delete their accounts.

The program saves user information in a CSV file called `users.csv`.

## 2. Features

The program can:

- **Register:** Create a new user account.
- **Login:** Allow registered users to access their accounts.
- **View Profile:** Display a user's personal details, if available in the dashboard.
- **Change Password:** Allow users to create a new password.
- **Delete Account:** Remove a user's account.
- **Search User:** Find a registered user using their username.
- **Logout:** Allow users to leave their accounts safely.

## 3. Tools Used

- Python
- CSV file for saving user information
- `hashlib` for password hashing
- `secrets` for creating random password salts
- `hmac` for safely checking passwords

## 4. How to Run the Program

Follow these steps:

1. Make sure Python is installed on your computer.
2. Open the project folder.
3. Open Command Prompt or PowerShell.
4. Run this command:

   `python main.py`

5. Follow the instructions displayed on the screen.

## 5. How the Program Works

1. A new user creates an account.
2. The program checks the user's information.
3. The password is hashed before it is saved.
4. The user can log in using their username and password.
5. The user can manage their account through the dashboard.

## 6. Project Files

- `main.py` – Contains the Python code.
- `users.csv` – Stores registered user information.
- `README.md` – Explains how to use the program.

## 7. Important Information

- Choose a password with at least 6 characters.
- Each username must be unique.
- Do not share your password with other people.
- Do not delete `users.csv` because it contains registered user information.
- Always keep a backup of your `users.csv` file.

## 8. Purpose of the Project

This project was created to practise Python programming.

It helps demonstrate the use of:

- Functions
- Loops
- Conditional statements
- Dictionaries
- File handling
- CSV files
- Error handling
- Password hashing

**Thank you for using the User Management System!**