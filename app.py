import streamlit as st
import pandas as pd
import os, json, hashlib, random, datetime

BOOKS_FILE = "books_data.json"
USERS_FILE = "users.json"

# ------------------ Helpers ------------------
def hash_password(p): return hashlib.sha256(p.encode()).hexdigest()

def load_users():
    if os.path.exists(USERS_FILE):
        try:
            return json.load(open(USERS_FILE))
        except:
            return []
    return []

def save_users(users): json.dump(users, open(USERS_FILE,"w"), indent=4)

def load_books():
    if os.path.exists(BOOKS_FILE):
        try:
            data = json.load(open(BOOKS_FILE))
            return pd.DataFrame(data)
        except:
            return pd.DataFrame(columns=["bid","title","author","category","status","issued_to","issue_date","due_date"])
    return pd.DataFrame(columns=["bid","title","author","category","status","issued_to","issue_date","due_date"])

def save_books(df): json.dump(df.to_dict(orient="records"), open(BOOKS_FILE,"w"), indent=4)

# ------------------ OTP Simulation ------------------
def generate_otp():
    return str(random.randint(100000,999999))

def send_otp_simulated(contact, otp):
    # In production: integrate email/SMS API here
    st.info(f"(Simulation) OTP sent to {contact}: **{otp}**")

# ------------------ Auth Functions ------------------
def signup(username, password, role, email, phone):
    users = load_users()
    if any(u["username"]==username for u in users):
        return False
    users.append({
        "username": username,
        "password": hash_password(password),
        "role": role,
        "email": email,
        "phone": phone
    })
    save_users(users)
    return True

def check_credentials(username, password):
    users = load_users()
    for u in users:
        if u["username"]==username and u["password"]==hash_password(password):
            return u
    return None

def update_password(username, new_password):
    users = load_users()
    for u in users:
        if u["username"]==username:
            u["password"]=hash_password(new_password)
            save_users(users)
            return True
    return False

# ------------------ Streamlit App ------------------
st.set_page_config(page_title="Library Auth", page_icon="📚")

if "auth_stage" not in st.session_state:
    st.session_state.auth_stage = "login" # login, otp, forgot, reset
if "pending_user" not in st.session_state:
    st.session_state.pending_user = None
if "otp" not in st.session_state:
    st.session_state.otp = None

st.title("📚 Library Management System")

# ---------- SIGN UP ----------
with st.expander("Sign Up (New User)"):
    new_user = st.text_input("Username", key="su_user")
    new_pass = st.text_input("Password", type="password", key="su_pass")
    new_email = st.text_input("Email", key="su_email")
    new_phone = st.text_input("Phone Number", key="su_phone")
    new_role = st.selectbox("Role", ["student","admin"], key="su_role")
    if st.button("Create Account"):
        if signup(new_user,new_pass,new_role,new_email,new_phone):
            st.success("✅ Account created. You can login now.")
        else:
            st.error("Username already exists.")

# ---------- FORGOT PASSWORD ----------
with st.expander("Forgot Password?"):
    if st.session_state.auth_stage == "forgot":
        st.write("Enter OTP sent to your registered contact:")
        otp_input = st.text_input("OTP")
        if st.button("Verify OTP"):
            if otp_input == st.session_state.otp:
                st.session_state.auth_stage = "reset"
                st.success("OTP Verified! Now set a new password.")
            else:
                st.error("Invalid OTP.")
    elif st.session_state.auth_stage == "reset":
        new_pass = st.text_input("New Password", type="password")
        if st.button("Reset Password"):
            if update_password(st.session_state.pending_user, new_pass):
                st.success("Password reset! You can now log in.")
                st.session_state.auth_stage = "login"
                st.session_state.pending_user = None
            else:
                st.error("Error resetting password.")
    else:
        forgot_user = st.text_input("Username", key="fp_user")
        if st.button("Send OTP"):
            user = next((u for u in load_users() if u["username"]==forgot_user), None)
            if user:
                otp = generate_otp()
                st.session_state.otp = otp
                st.session_state.pending_user = forgot_user
                send_otp_simulated(user["email"] or user["phone"], otp)
                st.session_state.auth_stage = "forgot"
            else:
                st.error("Username not found.")

# ---------- LOGIN ----------
if st.session_state.auth_stage == "login":
    login_user = st.text_input("Username")
    login_pass = st.text_input("Password", type="password")
    if st.button("Login"):
        user = check_credentials(login_user, login_pass)
        if user:
            otp = generate_otp()
            st.session_state.otp = otp
            st.session_state.pending_user = login_user
            send_otp_simulated(user["email"] or user["phone"], otp)
            st.session_state.auth_stage = "otp"
        else:
            st.error("Invalid credentials.")

# ---------- OTP STEP ----------
if st.session_state.auth_stage == "otp":
    st.write("Enter the OTP sent to your contact:")
    otp_input = st.text_input("OTP")
    if st.button("Verify and Login"):
        if otp_input == st.session_state.otp:
            st.success(f"✅ Logged in as {st.session_state.pending_user}")
            st.session_state.logged_in = True
            st.session_state.username = st.session_state.pending_user
            st.session_state.auth_stage = "loggedin"
        else:
            st.error("Incorrect OTP.")

# ---------- MAIN DASHBOARD AFTER LOGIN ----------
if st.session_state.get("logged_in", False):
    st.subheader(f"Welcome, {st.session_state.username}!")
    # load books etc.
    books_df = load_books()
    st.dataframe(books_df)
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.auth_stage = "login"
        st.experimental_rerun()
