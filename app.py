import streamlit as st
import pandas as pd
import os, json, hashlib, random, datetime

# ----------------------
# File Paths
# ----------------------
BOOKS_FILE = "books_data.json"
USERS_FILE = "users.json"

# ----------------------
# Helper Functions
# ----------------------
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
            df = pd.DataFrame(data)
            for col in ["issued_to","issue_date","due_date"]:
                if col not in df.columns: df[col] = ""
            return df
        except:
            return pd.DataFrame(columns=["bid","title","author","category","status","issued_to","issue_date","due_date"])
    return pd.DataFrame(columns=["bid","title","author","category","status","issued_to","issue_date","due_date"])

def save_books(df): json.dump(df.to_dict(orient="records"), open(BOOKS_FILE,"w"), indent=4)

# ----------------------
# OTP Functions (simulate or integrate with email/SMS)
# ----------------------
def generate_otp(): return str(random.randint(100000,999999))

def send_otp(contact, otp):
    # 🚀 TODO: integrate real email/SMS API
    st.info(f"(Simulation) OTP sent to {contact}: **{otp}**")

# ----------------------
# Auth Functions
# ----------------------
def signup(username, password, role, email, phone):
    users = load_users()
    if any(u["username"]==username for u in users): return False
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

# ----------------------
# Streamlit State Setup
# ----------------------
st.set_page_config(page_title="Library System", page_icon="📚", layout="wide")

for key, val in {
    "auth_stage":"login",
    "pending_user":None,
    "otp":None,
    "logged_in":False,
    "username":"",
    "role":""
}.items():
    if key not in st.session_state: st.session_state[key]=val

# ----------------------
# UI - Sign Up
# ----------------------
with st.expander("📝 Sign Up"):
    su_user = st.text_input("Username", key="su_user")
    su_pass = st.text_input("Password", type="password", key="su_pass")
    su_email = st.text_input("Email", key="su_email")
    su_phone = st.text_input("Phone", key="su_phone")
    su_role = st.selectbox("Role", ["student","admin"], key="su_role")
    if st.button("Create Account"):
        if signup(su_user,su_pass,su_role,su_email,su_phone):
            st.success("✅ Account created! You can login now.")
        else:
            st.error("Username already exists.")

# ----------------------
# UI - Forgot Password
# ----------------------
with st.expander("🔑 Forgot Password"):
    if st.session_state.auth_stage == "forgot":
        otp_input = st.text_input("Enter OTP")
        if st.button("Verify OTP"):
            if otp_input == st.session_state.otp:
                st.session_state.auth_stage = "reset"
                st.success("OTP verified! Now set a new password.")
            else:
                st.error("Invalid OTP.")
    elif st.session_state.auth_stage == "reset":
        newp = st.text_input("New Password", type="password")
        if st.button("Reset Password"):
            if update_password(st.session_state.pending_user, newp):
                st.success("✅ Password reset. Please login.")
                st.session_state.auth_stage="login"
                st.session_state.pending_user=None
            else:
                st.error("Error resetting password.")
    else:
        fp_user = st.text_input("Username", key="fp_user")
        if st.button("Send OTP"):
            user = next((u for u in load_users() if u["username"]==fp_user), None)
            if user:
                otp = generate_otp()
                st.session_state.otp = otp
                st.session_state.pending_user = fp_user
                send_otp(user.get("email") or user.get("phone"), otp)
                st.session_state.auth_stage="forgot"
            else:
                st.error("User not found.")

# ----------------------
# UI - Login
# ----------------------
if st.session_state.auth_stage == "login" and not st.session_state.logged_in:
    st.subheader("🔐 Login")
    login_user = st.text_input("Username")
    login_pass = st.text_input("Password", type="password")
    if st.button("Login"):
        user = check_credentials(login_user, login_pass)
        if user:
            otp = generate_otp()
            st.session_state.otp = otp
            st.session_state.pending_user = login_user
            send_otp(user.get("email") or user.get("phone"), otp)
            st.session_state.auth_stage = "otp"
        else:
            st.error("Invalid credentials.")

# ----------------------
# OTP Step
# ----------------------
if st.session_state.auth_stage == "otp":
    otp_input = st.text_input("Enter OTP sent to your contact")
    if st.button("Verify and Login"):
        if otp_input == st.session_state.otp:
            st.session_state.logged_in = True
            st.session_state.username = st.session_state.pending_user
            # get role
            u = next((u for u in load_users() if u["username"]==st.session_state.username),None)
            st.session_state.role = u["role"] if u else ""
            st.session_state.auth_stage = "loggedin"
            st.success(f"✅ Logged in as {st.session_state.username}")
        else:
            st.error("Incorrect OTP.")

# ----------------------
# Main Dashboard
# ----------------------
if st.session_state.logged_in:
    books_df = load_books()

    menu_options = ["View Books", "Issue Book", "Return Book", "View Issued Books", "Logout"]
    if st.session_state.role == "admin":
        menu_options = ["View Books", "Add Book", "Delete Book", "Issue Book", "Return Book", "View Issued Books", "Logout"]

    menu = st.sidebar.radio("Menu", menu_options)

    if menu == "View Books":
        st.header("📘 All Books")
        st.dataframe(books_df)

    elif menu == "Add Book":
        st.header("➕ Add Book")
        bid = st.number_input("Book ID", min_value=1, step=1)
        title = st.text_input("Title")
        author = st.text_input("Author")
        category = st.text_input("Category")
        if st.button("Add Book"):
            if bid and title and author and category:
                if bid in books_df["bid"].values:
                    st.error("Book ID exists.")
                else:
                    new_book = pd.DataFrame([{ "bid": bid, "title": title, "author": author, "category": category, "status": "available", "issued_to": "", "issue_date": "", "due_date": "" }])
                    books_df = pd.concat([books_df,new_book], ignore_index=True)
                    save_books(books_df)
                    st.success("✅ Book added.")

    elif menu == "Delete Book":
        st.header("❌ Delete Book")
        if not books_df.empty:
            bid = st.selectbox("Select Book ID", books_df["bid"])
            if st.button("Delete"):
                books_df = books_df[books_df["bid"]!=bid]
                save_books(books_df)
                st.success("✅ Book deleted.")

    elif menu == "Issue Book":
        st.header("📤 Issue Book")
        available_books = books_df[books_df["status"]=="available"]
        if available_books.empty:
            st.info("No available books.")
        else:
            bid = st.selectbox("Select Book", available_books["bid"], format_func=lambda x: f"{x} - {available_books[available_books['bid']==x]['title'].values[0]}")
            student = st.session_state.username if st.session_state.role=="student" else st.text_input("Student Username")
            if st.button("Issue"):
                idx = books_df[books_df["bid"]==bid].index[0]
                today = datetime.date.today()
                due = today + datetime.timedelta(days=7)
                books_df.at[idx,"status"]="issued"
                books_df.at[idx,"issued_to"]=student
                books_df.at[idx,"issue_date"]=str(today)
                books_df.at[idx,"due_date"]=str(due)
                save_books(books_df)
                st.success(f"✅ Book issued to {student} (Due {due})")

    elif menu == "Return Book":
        st.header("📥 Return Book")
        if st.session_state.role=="admin":
            issued_books = books_df[books_df["status"]=="issued"]
        else:
            issued_books = books_df[(books_df["status"]=="issued") & (books_df["issued_to"]==st.session_state.username)]
        if issued_books.empty:
            st.info("No issued books.")
        else:
            bid = st.selectbox("Select Book", issued_books["bid"], format_func=lambda x: f"{x} - {issued_books[issued_books['bid']==x]['title'].values[0]}")
            if st.button("Return"):
                idx = books_df[books_df["bid"]==bid].index[0]
                today = datetime.date.today()
                due_date = datetime.date.fromisoformat(books_df.at[idx,"due_date"])
                fine = max(0,(today-due_date).days*5)
                books_df.at[idx,"status"]="available"
                books_df.at[idx,"issued_to"]=""
                books_df.at[idx,"issue_date"]=""
                books_df.at[idx,"due_date"]=""
                save_books(books_df)
                if fine>0:
                    st.warning(f"Returned late! Fine: ₹{fine}")
                else:
                    st.success("✅ Book returned on time.")

    elif menu == "View Issued Books":
        st.header("📋 Issued Books")
        if st.session_state.role=="admin":
            issued = books_df[books_df["status"]=="issued"]
        else:
            issued = books_df[(books_df["status"]=="issued") & (books_df["issued_to"]==st.session_state.username)]
        if issued.empty:
            st.info("No books issued.")
        else:
            st.dataframe(issued[["bid","title","author","category","issued_to","issue_date","due_date"]])

    elif menu == "Logout":
        st.session_state.logged_in=False
        st.session_state.auth_stage="login"
        st.session_state.username=""
        st.session_state.role=""
        st.experimental_rerun()
