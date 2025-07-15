import streamlit as st
import requests
import sqlite3
import hashlib
from streamlit_cookies_manager import CookieManager
import pandas as pd

DB_NAME = "users.db"

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS urls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        original_url TEXT NOT NULL,
        short_url TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

# --- Password Hashing ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --- User Management ---
def register_user(email, password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hash_password(password)))
        conn.commit()
        return True, "Registration successful."
    except sqlite3.IntegrityError:
        return False, "Email already registered."
    finally:
        conn.close()

def login_user(email, password):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, password FROM users WHERE email = ?", (email,))
    row = c.fetchone()
    conn.close()
    if row and row[1] == hash_password(password):
        return True, row[0]  # Success, user_id
    return False, None

def get_user_by_id(user_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, email FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    return row

# --- URL Management ---
def save_url(user_id, original_url, short_url):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("INSERT INTO urls (user_id, original_url, short_url) VALUES (?, ?, ?)", (user_id, original_url, short_url))
    conn.commit()
    conn.close()

def get_user_urls(user_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT original_url, short_url FROM urls WHERE user_id = ? ORDER BY id DESC", (user_id,))
    urls = c.fetchall()
    conn.close()
    return urls

# --- Streamlit App ---
init_db()

cookies = CookieManager()

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user_id = None
    st.session_state.email = None

# Check cookie for persistent login
def try_cookie_login():
    if cookies.ready:
        user_id = cookies["user_id"] if "user_id" in cookies else None
        if user_id and not st.session_state.logged_in:
            user = get_user_by_id(user_id)
            if user:
                st.session_state.logged_in = True
                st.session_state.user_id = user[0]
                st.session_state.email = user[1]
    else:
        st.stop()

try_cookie_login()

if not cookies.ready:
    st.stop()

st.title("NanoURLs")

# Sidebar navigation
if st.session_state.logged_in:
    page = st.sidebar.radio("Navigation", ["Shorten URL", "Profile", "Logout"])
else:
    page = "Shorten URL"

if not st.session_state.logged_in:
    tab1, tab2 = st.tabs(["Login", "Register"])
    with tab1:
        st.subheader("Login")
        email = st.text_input("Email", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login"):
            ok, user_id = login_user(email, password)
            if ok:
                st.session_state.logged_in = True
                st.session_state.user_id = user_id
                st.session_state.email = email
                cookies["user_id"] = str(user_id)
                cookies.save()
                st.success("Logged in successfully!")
                st.rerun()
            else:
                st.error("Invalid email or password.")
    with tab2:
        st.subheader("Register")
        reg_email = st.text_input("Email", key="reg_email")
        reg_password = st.text_input("Password", type="password", key="reg_password")
        if st.button("Register"):
            ok, msg = register_user(reg_email, reg_password)
            if ok:
                st.success(msg)
            else:
                st.error(msg)
else:
    st.sidebar.write(f"Logged in as: {st.session_state.email}")
    if page == "Logout":
        st.session_state.logged_in = False
        st.session_state.user_id = None
        st.session_state.email = None
        if "user_id" in cookies:
            del cookies["user_id"]
            cookies.save()
        st.rerun()
    elif page == "Shorten URL":
        st.header("Shorten a URL")
        long_url = st.text_input("Paste your long URL here:")
        if st.button("Shorten URL"):
            if not long_url or not long_url.strip():
                st.warning("Please enter a valid URL.")
            elif not (long_url.startswith("http://") or long_url.startswith("https://")):
                st.warning("URL must start with http:// or https://")
            else:
                try:
                    res = requests.get("https://nanourls2.onrender.com/shorten", params={"url": long_url}, timeout=10)
                    if res.status_code == 200:
                        short_url = res.json().get("short_url")
                        if short_url:
                            st.success(f"Short URL: {short_url}")
                            save_url(st.session_state.user_id, long_url, short_url)
                        else:
                            st.error("Unexpected response from server. Please try again.")
                    else:
                        st.error(f"Server returned {res.status_code}: {res.text}")
                except Exception as e:
                    st.error(f"Failed to connect to shortening service.\n\n{e}")
    elif page == "Profile":
        st.header("Your Profile: URLs History")
        urls = get_user_urls(st.session_state.user_id)
        if urls:
            df = pd.DataFrame(urls, columns=["Original URL", "Short URL"])  # type: ignore
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No URLs shortened yet.")