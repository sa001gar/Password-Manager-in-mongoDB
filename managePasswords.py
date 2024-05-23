import random
import string
import bcrypt
from pymongo import MongoClient
from datetime import datetime

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client.password_manager_db


# UserManager Class: Manages user-related operations
class UserManager:
    def __init__(self):
        # Connect to user Database
        self.users_collection = db.users

    # Method to create a new user
    def create_user(self, username, password):
        if self.users_collection.find_one({"username": username}):
            return "Username already exists"

        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        self.users_collection.insert_one({"username": username, "password": hashed})
        return "User created successfully"

    # Method to authenticate a user
    def authenticate_user(self, username, password):
        user = self.users_collection.find_one({"username": username})
        if user and bcrypt.checkpw(password.encode("utf-8"), user["password"]):
            return True
        return False

    # Method to delete a user
    def delete_user(self, username, password):
        user = self.users_collection.find_one({"username": username})
        if user and bcrypt.checkpw(password.encode("utf-8"), user["password"]):
            # Delete user's passwords
            db.passwords.delete_many({"username": username})
            # Delete user
            self.users_collection.delete_one({"username": username})
            return "User and all associated passwords deleted successfully"
        return "Authentication failed or user does not exist"


# PasswordManager Class: Manages password-related operations
class PasswordManager:
    def __init__(self, username):
        self.username = username
        self.passwords_collection = db.passwords

    # Method to generate a random password
    def generate_password(self, length=10):
        characters = string.ascii_letters + string.digits + "@$"
        password = "".join(random.choice(characters) for i in range(length))
        return password

    # Method to save a password entry
    def save_password(self, service_name, use, platform, password=None):
        if not password:
            password = self.generate_password()
        self.passwords_collection.insert_one(
            {
                "username": self.username,
                "service_name": service_name,
                "use": use,
                "platform": platform,
                "password": password,
                "timestamp": datetime.now(),
            }
        )

    # Method to update a password entry
    def update_password(self, service_name, new_password):
        result = self.passwords_collection.update_one(
            {"username": self.username, "service_name": service_name},
            {"$set": {"password": new_password, "timestamp": datetime.now()}},
        )
        return result.modified_count > 0

    # Method to delete a password entry
    def delete_password(self, service_name):
        result = self.passwords_collection.delete_one(
            {"username": self.username, "service_name": service_name}
        )
        return result.deleted_count > 0

    # Method to view all password entries
    def view_all_passwords(self):
        passwords = self.passwords_collection.find({"username": self.username})
        return list(passwords)


# Main function: Entry point of the program
def main():
    user_manager = UserManager()

    # Example usage and user interaction
    print("Welcome to the Password Manager")

    while True:
        print("\nSelect an option:")
        print("1. Create user")
        print("2. Login")
        print("3. Delete user")
        print("4. Exit")
        option = input("Enter option number: ")

        if option == "1":
            username = input("Enter username: ")
            password = input("Enter password: ")
            print(user_manager.create_user(username, password))
        elif option == "2":
            username = input("Enter username: ")
            password = input("Enter password: ")
            if user_manager.authenticate_user(username, password):
                print("Authentication successful")
                password_manager = PasswordManager(username)

                while True:
                    print("\nSelect an option:")
                    print("1. Create password entry")
                    print("2. Update password entry")
                    print("3. Delete password entry")
                    print("4. View all password entries")
                    print("5. Logout")
                    option = input("Enter option number: ")

                    if option == "1":
                        service_name = input("Enter service or user name: ")
                        use = input("Enter use of the password: ")
                        platform = input("Enter platform: ")
                        custom_password = input(
                            "Enter custom password (leave blank to generate): "
                        )
                        password_manager.save_password(
                            service_name, use, platform, custom_password
                        )
                        print("Password entry saved.")
                    elif option == "2":
                        service_name = input("Enter service or user name to update: ")
                        new_password = input("Enter new password: ")
                        if password_manager.update_password(service_name, new_password):
                            print("Password updated.")
                        else:
                            print("Service not found.")
                    elif option == "3":
                        service_name = input("Enter service or user name to delete: ")
                        if password_manager.delete_password(service_name):
                            print("Password entry deleted.")
                        else:
                            print("Service not found.")
                    elif option == "4":
                        passwords = password_manager.view_all_passwords()
                        for pw in passwords:
                            print(
                                f"\nService: {pw['service_name']} \n Use: {pw['use']} \n Platform: {pw['platform']} \n Password: {pw['password']} \n Stored At: {pw['timestamp']}"
                            )
                    elif option == "5":
                        break
                    else:
                        print("Invalid option. Please try again.")
            else:
                print("Authentication failed.")
        elif option == "3":
            username = input("Enter username to delete: ")
            password = input("Enter password to confirm: ")
            print(user_manager.delete_user(username, password))
        elif option == "4":
            break
        else:
            print("Invalid option. Please try again.")


# Entry point of the program
if __name__ == "__main__":
    main()
