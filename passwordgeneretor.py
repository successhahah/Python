import secrets
import string
import hashlib
import pyperclip
import time
import getpass


def generate_password(length=12, use_digits=True, use_special_chars=True):
    if length < 6:
        raise ValueError("Password length should be at least 6 characters.")
    
    characters = string.ascii_letters
    if use_digits:
        characters += string.digits
    if use_special_chars:
        special_chars = "!@#$%^&*()-_=+[]{}|;:'\",.<>?/"
        characters += special_chars
    
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password


def generate_passphrase(word_count=4):
    words = [secrets.choice(string.ascii_lowercase) for _ in range(word_count)]
    return '-'.join(words)


def hash_password(password, algorithm='sha256'):
    if algorithm == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(password.encode()).hexdigest()
    elif algorithm == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    else:
        raise ValueError("Unsupported hashing algorithm.")


def copy_to_clipboard(password):
    pyperclip.copy(password)
    print("Password copied to clipboard!")


def display_password_stats(password):
    length = len(password)
    digits = sum(c.isdigit() for c in password)
    special_chars = sum(c in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/" for c in password)
    print(f"\nPassword Stats:\nLength: {length}\nDigits: {digits}\nSpecial Characters: {special_chars}")

# Get user input for Yes/No
def get_boolean_input(prompt):
    while True:
        response = input(prompt).strip().lower()
        if response in ['y', 'n']:
            return response == 'y'
        print("Invalid input. Please enter 'y' or 'n'.")

# Delay message display
def delay_message(message, delay=2):
    time.sleep(delay)
    print(message)

if __name__ == "__main__":
    while True:
        try:
            password_length = int(input("Enter password length (minimum 6): "))
            if password_length < 6:
                print("Password length should be at least 6 characters.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a valid number.")
    
    include_digits = get_boolean_input("Include digits? (y/n): ")
    include_special_chars = get_boolean_input("Include special characters? (y/n): ")
    
    password = generate_password(password_length, include_digits, include_special_chars)
    display_password_stats(password)
    
    # Choose hashing algorithm
    print("\nChoose hashing algorithm: 1) SHA-256  2) SHA-512  3) MD5")
    algo_choice = input("Enter choice (1/2/3): ")
    algo_dict = {'1': 'sha256', '2': 'sha512', '3': 'md5'}
    hash_algo = algo_dict.get(algo_choice, 'sha256')
    
    password_hash = hash_password(password, hash_algo)
    print("\nGenerated password:", password)
    print(f"{hash_algo.upper()} Hash:", password_hash)
    
    copy_option = get_boolean_input("Copy password to clipboard? (y/n): ")
    if copy_option:
        copy_to_clipboard(password)
    
    delay_message("Thank you for using the Password Generator!")
