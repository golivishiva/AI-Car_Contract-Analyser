import sqlite3
import bcrypt
from datetime import datetime
import streamlit as st

def get_auth_connection():
    """Get database connection for auth"""
    conn = sqlite3.connect('contracts.db')
    return conn

def init_auth_tables():
    """Initialize authentication tables"""
    conn = get_auth_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # ✅ ADD user_id to contracts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS contracts_temp (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT,
            created_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Check if contracts table has user_id column
    cursor.execute("PRAGMA table_info(contracts)")
    columns = [col[1] for col in cursor.fetchall()]
    
    if 'user_id' not in columns and 'contracts' in [table[0] for table in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]:
        # Migrate existing contracts table
        cursor.execute("ALTER TABLE contracts ADD COLUMN user_id INTEGER DEFAULT 1")
    
    # ✅ ADD user_id to chat_messages table
    cursor.execute("PRAGMA table_info(chat_messages)")
    columns = [col[1] for col in cursor.fetchall()]
    
    if 'chat_messages' in [table[0] for table in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]:
        if 'user_id' not in columns:
            cursor.execute("ALTER TABLE chat_messages ADD COLUMN user_id INTEGER DEFAULT 1")
    
    conn.commit()
    conn.close()

def register_user(username: str, password: str, email: str = None):
    """Register a new user"""
    conn = get_auth_connection()
    cursor = conn.cursor()
    
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    try:
        cursor.execute(
            'INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
            (username, password_hash, email)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        return True, user_id
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Username already exists"
    except Exception as e:
        conn.close()
        return False, str(e)

def verify_user(username: str, password: str):
    """Verify user credentials"""
    conn = get_auth_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user[1]):
        return True, user[0]
    return False, None

def log_login(user_id: int, ip_address: str = "unknown"):
    """Log user login"""
    conn = get_auth_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        'INSERT INTO login_history (user_id, ip_address) VALUES (?, ?)',
        (user_id, ip_address)
    )
    cursor.execute(
        'UPDATE users SET last_login = ? WHERE id = ?',
        (datetime.now(), user_id)
    )
    
    conn.commit()
    conn.close()

def get_user_info(user_id: int):
    """Get user information"""
    conn = get_auth_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT username, email, created_at, last_login FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {
            'username': user[0],
            'email': user[1],
            'created_at': user[2],
            'last_login': user[3]
        }
    return None

def show_login_page():
    """Display login page"""
    st.markdown("""
        <div style="text-align: center; margin-bottom: 2rem;">
            <h1>🚗 Contract AI Login</h1>
            <p>Sign in to analyze your car contracts</p>
        </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2 = st.tabs(["Login", "Register"])
    
    with tab1:
        with st.form("login_form"):
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")
            submit = st.form_submit_button("Login", use_container_width=True)
            
            if submit:
                if not username or not password:
                    st.error("Please enter both username and password")
                else:
                    success, user_id = verify_user(username, password)
                    if success:
                        st.session_state.logged_in = True
                        st.session_state.user_id = user_id
                        st.session_state.username = username
                        log_login(user_id)
                        st.success("Login successful!")
                        st.rerun()
                    else:
                        st.error("Invalid username or password")
    
    with tab2:
        with st.form("register_form"):
            new_username = st.text_input("Username", key="reg_username")
            new_email = st.text_input("Email (optional)", key="reg_email")
            new_password = st.text_input("Password", type="password", key="reg_password")
            confirm_password = st.text_input("Confirm Password", type="password", key="reg_confirm")
            register = st.form_submit_button("Register", use_container_width=True)
            
            if register:
                if not new_username or not new_password:
                    st.error("Username and password are required")
                elif new_password != confirm_password:
                    st.error("Passwords do not match")
                elif len(new_password) < 6:
                    st.error("Password must be at least 6 characters")
                else:
                    success, result = register_user(new_username, new_password, new_email)
                    if success:
                        st.success("Registration successful! Please login.")
                    else:
                        st.error(f"Registration failed: {result}")

def check_authentication():
    """Check if user is authenticated"""
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    
    if not st.session_state.logged_in:
        show_login_page()
        st.stop()

def logout():
    """Logout user"""
    st.session_state.logged_in = False
    st.session_state.user_id = None
    st.session_state.username = None
    st.session_state.chat_history = []
    st.session_state.contracts_context = {}
    st.session_state.active_contract_id = None
    st.rerun()