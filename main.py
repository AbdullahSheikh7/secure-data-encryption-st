import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Initialize session state variables if they don't exist
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'last_failed_time' not in st.session_state:
    st.session_state.last_failed_time = 0
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'is_authenticated' not in st.session_state:
    st.session_state.is_authenticated = False

# File to store encrypted data
DATA_FILE = "encrypted_data.json"
USERS_FILE = "users.json"

# Generate a key (this should be stored securely in production)
KEY = st.secrets["secret"]
cipher = Fernet(KEY)

# Load data from file if it exists
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            try:
                return json.load(f)
            except:
                return {}
    return {}

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            try:
                return json.load(f)
            except:
                return {}
    return {}

# Save data to file
def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

# Save users to file
def save_users(data):
    with open(USERS_FILE, 'w') as f:
        json.dump(data, f)

# In-memory data storage with file persistence
stored_data = load_data()

# Function to hash passkey using PBKDF2 (more secure than SHA-256)
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return key.decode(), base64.b64encode(salt).decode()

# Function to verify passkey
def verify_passkey(passkey, stored_key, stored_salt):
    salt = base64.b64decode(stored_salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return key.decode() == stored_key

# Function to encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey, data_id, username):
    if username not in stored_data or data_id not in stored_data[username]:
        return None
    
    data_entry = stored_data[username][data_id]
    stored_key = data_entry["passkey"]
    stored_salt = data_entry["salt"]
    
    if verify_passkey(passkey, stored_key, stored_salt):
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    
    st.session_state.failed_attempts += 1
    st.session_state.last_failed_time = time.time()
    return None

# Function to check if user is in timeout
def is_in_timeout():
    # 30 seconds timeout after 3 failed attempts
    if st.session_state.failed_attempts >= 3:
        elapsed_time = time.time() - st.session_state.last_failed_time
        if elapsed_time < 30:
            return True, 30 - int(elapsed_time)
    return False, 0

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# User authentication
def login_page():
    login, signup = st.tabs(["Login", "Signup"])

    login_data = load_users()

    with login:
        st.subheader("👤 User Login")
        login_username = st.text_input("Username", key="login_username")
        login_password = st.text_input("Password", type="password", key="login_password")

        if st.button("Login"):
            if login_username and login_password:
                if login_username in login_data.keys() and login_password == login_data.get(login_username):
                    st.session_state.current_user = login_username
                    st.session_state.is_authenticated = True
                    st.session_state.failed_attempts = 0
                    st.success(f"✅ Welcome, {login_username}!")
                    st.rerun()
                else:
                    st.error("❌ Invalid username or password")
            else:
                st.error("⚠️ Username and password are required!")

    with signup:
        st.subheader("👤 User Signup")
        signup_username = st.text_input("Username", key="signup_username")
        signup_password = st.text_input("Password", type="password", key="signup_password")

        if st.button("Signup"):
            if signup_username in login_data.keys():
                st.error("⚠️ Username already exists. Try loging in")
            elif signup_username and signup_password:
                login_data[signup_username] = signup_password
                save_users(login_data)
                st.session_state.current_user = signup_username
                st.session_state.is_authenticated = True
                st.session_state.failed_attempts = 0
                st.success(f"✅ Welcome, {signup_username}!")
                st.rerun()
            else:
                st.error("⚠️ Username and password are required!")

# Navigation
if not st.session_state.is_authenticated:
    login_page()
else:
    # Initialize user data if not exists
    if st.session_state.current_user not in stored_data:
        stored_data[st.session_state.current_user] = {}
        save_data(stored_data)
    
    # Check for timeout
    timeout, remaining = is_in_timeout()
    if timeout:
        st.error(f"🔒 Account locked due to too many failed attempts. Try again in {remaining} seconds.")
        if st.button("Return to Login"):
            st.session_state.is_authenticated = False
            st.rerun()
    else:
        menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
        choice = st.sidebar.selectbox("Navigation", menu)
        
        st.sidebar.write(f"Logged in as: **{st.session_state.current_user}**")
        
        if choice == "Home":
            st.subheader("🏠 Welcome to the Secure Data System")
            st.write(f"Hello, **{st.session_state.current_user}**! Use this app to **securely store and retrieve data** using unique passkeys.")
            st.write("Your data is encrypted and can only be accessed with the correct passkey.")
            
            # Show user's stored data count
            user_data = stored_data.get(st.session_state.current_user, {})
            st.info(f"You have {len(user_data)} encrypted data entries stored.")
        
        elif choice == "Store Data":
            st.subheader("📂 Store Data Securely")
            data_name = st.text_input("Data Name (for reference):")
            user_data = st.text_area("Enter Data:")
            passkey = st.text_input("Enter Passkey:", type="password")
            
            if st.button("Encrypt & Save"):
                if user_data and passkey and data_name:
                    # Generate a unique ID for this data entry
                    data_id = str(int(time.time()))
                    
                    # Hash the passkey with PBKDF2
                    hashed_passkey, salt = hash_passkey(passkey)
                    
                    # Encrypt the data
                    encrypted_text = encrypt_data(user_data)
                    
                    # Store the data
                    if st.session_state.current_user not in stored_data:
                        stored_data[st.session_state.current_user] = {}
                    
                    stored_data[st.session_state.current_user][data_id] = {
                        "name": data_name,
                        "encrypted_text": encrypted_text,
                        "passkey": hashed_passkey,
                        "salt": salt,
                        "timestamp": time.time()
                    }
                    
                    # Save to file
                    save_data(stored_data)
                    
                    st.success("✅ Data stored securely!")
                else:
                    st.error("⚠️ All fields are required!")
        
        elif choice == "Retrieve Data":
            st.subheader("🔍 Retrieve Your Data")
            
            user_data = stored_data.get(st.session_state.current_user, {})
            
            if not user_data:
                st.warning("You don't have any stored data yet.")
            else:
                # Create a list of data entries for selection
                data_options = {f"{data['name']} (saved on {time.strftime('%Y-%m-%d %H:%M', time.localtime(data['timestamp']))})" : data_id 
                               for data_id, data in user_data.items()}
                
                selected_data_name = st.selectbox("Select Data to Retrieve:", list(data_options.keys()))
                selected_data_id = data_options[selected_data_name]
                
                passkey = st.text_input("Enter Passkey:", type="password")
                
                if st.button("Decrypt"):
                    if passkey:
                        encrypted_text = user_data[selected_data_id]["encrypted_text"]
                        decrypted_text = decrypt_data(encrypted_text, passkey, selected_data_id, st.session_state.current_user)
                        
                        if decrypted_text:
                            st.success("✅ Data decrypted successfully!")
                            st.code(decrypted_text)
                        else:
                            remaining_attempts = 3 - st.session_state.failed_attempts
                            st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining_attempts}")
                            
                            if st.session_state.failed_attempts >= 3:
                                st.warning("🔒 Too many failed attempts! Account locked for 30 seconds.")
                                st.rerun()
                    else:
                        st.error("⚠️ Passkey is required!")
        
        elif choice == "Logout":
            st.subheader("👋 Logout")
            st.write("Are you sure you want to logout?")
            
            if st.button("Confirm Logout"):
                st.session_state.is_authenticated = False
                st.session_state.current_user = None
                st.success("You have been logged out successfully!")
                st.rerun()
