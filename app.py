from flask import Flask, render_template, request, redirect, url_for, session, g, flash
import pandas as pd
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from pip._vendor import cachecontrol
import google.auth.transport.requests
import os
import pathlib
import requests
from functools import wraps
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace with a secure secret key

# Google OAuth2 configuration
GOOGLE_CLIENT_ID = "45595925952-kpjdqmr8lvvkng06o6nigohhuoac1gre.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"
@app.template_filter('datetime')
def parse_datetime(value):
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")

# OAuth2 configuration
client_secrets_file = "./cred.json"  
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ],
    redirect_uri="https://foundersmail.vercel.app/callback"
)

db_path = "database.db"

# Default view limit for free users
DEFAULT_VIEW_LIMIT = 5

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def is_admin():
    # For demo purposes, you might want to hardcode some admin emails
    admin_emails = ['odelapradeep12@gmail.com', 'your_email@gmail.com']
    if "user" in session and session["user"]["email"] in admin_emails:
        return True
    return False

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(db_path, check_same_thread=False)
        db.row_factory = sqlite3.Row  # This allows access to columns by name
    return db

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            email TEXT UNIQUE,
                            name TEXT,
                            created_at TEXT,
                            last_login TEXT,
                            subscription_type TEXT DEFAULT 'free',
                            lead_view_limit INTEGER DEFAULT 5)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS lead_views (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER,
                            lead_index INTEGER,
                            viewed_at TEXT,
                            FOREIGN KEY (user_id) REFERENCES users(id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_sessions (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_id INTEGER,
                            login_time TEXT,
                            logout_time TEXT,
                            FOREIGN KEY (user_id) REFERENCES users(id))''')
        # Create leads_data table if it doesn't exist
        cursor.execute('''CREATE TABLE IF NOT EXISTS leads_data (
                            id INTEGER PRIMARY KEY,
                            Company_Name TEXT,
                            Industry TEXT,
                            Description TEXT)''')
        db.commit()

def record_login(email, name):
    db = get_db()
    cursor = db.cursor()
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    
    # Check if user exists
    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    
    if user:
        # Update existing user
        cursor.execute("UPDATE users SET last_login = ? WHERE email = ?", (now, email))
        user_id = user[0]
    else:
        # Create new user with default settings
        cursor.execute("INSERT INTO users (email, name, created_at, last_login, subscription_type, lead_view_limit) VALUES (?, ?, ?, ?, 'free', ?)",
                      (email, name, now, now, DEFAULT_VIEW_LIMIT))
        user_id = cursor.lastrowid
    
    # Record the login session
    cursor.execute("INSERT INTO user_sessions (user_id, login_time) VALUES (?, ?)", (user_id, now))
    
    db.commit()
    return user_id

def record_logout(user_id):
    if user_id:
        db = get_db()
        cursor = db.cursor()
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        
        # First, find the latest session ID that needs to be updated
        cursor.execute("""
            SELECT id FROM user_sessions 
            WHERE user_id = ? AND logout_time IS NULL
            ORDER BY login_time DESC LIMIT 1
        """, (user_id,))
        
        session_row = cursor.fetchone()
        if session_row:
            # Then update that specific session
            cursor.execute("""
                UPDATE user_sessions 
                SET logout_time = ?
                WHERE id = ?
            """, (now, session_row[0]))
            
        db.commit()

def record_lead_view(user_id, lead_index):
    db = get_db()
    cursor = db.cursor()
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO lead_views (user_id, lead_index, viewed_at) VALUES (?, ?, ?)",
                   (user_id, lead_index, now))
    db.commit()

def get_user_lead_views_count(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT COUNT(*) FROM lead_views WHERE user_id = ?", (user_id,))
    count = cursor.fetchone()[0]
    return count

def get_user_view_limit(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT lead_view_limit FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchone()
    
    if result is None:
        # Return default view limit if user not found
        return DEFAULT_VIEW_LIMIT
    
    return result[0]

def update_user_subscription(user_id, subscription_type, view_limit):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE users SET subscription_type = ?, lead_view_limit = ? WHERE id = ?",
                  (subscription_type, view_limit, user_id))
    db.commit()

def get_user_analytics(user_id):
    db = get_db()
    cursor = db.cursor()
    
    # Get basic user info
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    # Get session history
    cursor.execute("SELECT login_time, logout_time FROM user_sessions WHERE user_id = ? ORDER BY login_time DESC", (user_id,))
    sessions = cursor.fetchall()
    
    # Get lead view history - check if leads_data table exists first
    try:
        cursor.execute("""
            SELECT lv.lead_index, lv.viewed_at, ld.Company_Name 
            FROM lead_views lv
            LEFT JOIN leads_data ld ON lv.lead_index = ld.id
            WHERE lv.user_id = ? 
            ORDER BY lv.viewed_at DESC
        """, (user_id,))
        lead_views = cursor.fetchall()
    except sqlite3.OperationalError:
        # If leads_data doesn't exist or join fails
        cursor.execute("""
            SELECT lead_index, viewed_at, NULL as Company_Name
            FROM lead_views
            WHERE user_id = ?
            ORDER BY viewed_at DESC
        """, (user_id,))
        lead_views = cursor.fetchall()
    
    return {
        'user': user,
        'sessions': sessions,
        'lead_views': lead_views,
        'total_views': len(lead_views),
        'total_sessions': len(sessions)
    }

def load_leads(file_path):
    try:
        df = pd.read_csv(file_path)
        df['Description'] = df['Description'].fillna("No description available")
        df['Short Description'] = df['Description'].apply(lambda x: x[:50] + "..." if len(x) > 50 else x)
        
        # Store lead data in database for reference
        db = get_db()
        cursor = db.cursor()
        
        # Check if table exists before attempting operation
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='leads_data'")
        table_exists = cursor.fetchone() is not None
        
        if table_exists:
            # Clear existing data
            cursor.execute("DELETE FROM leads_data")
        else:
            # Create table if it doesn't exist
            cursor.execute("""
                CREATE TABLE leads_data (
                    id INTEGER PRIMARY KEY,
                    Company_Name TEXT,
                    Industry TEXT,
                    Description TEXT
                )
            """)
        
        # Insert lead data
        for idx, row in df.iterrows():
            cursor.execute("INSERT INTO leads_data VALUES (?, ?, ?, ?)",
                        (idx, row['Company Name'], row['Industry'], row['Description']))
        
        db.commit()
        
        leads = df.to_dict(orient='records')
        for i, lead in enumerate(leads):
            lead['index'] = i
        
        stats = {
            "total_leads": len(leads),
            "common_industry": max(set(df['Industry']), key=list(df['Industry']).count) if not df.empty else "None",
            "latest_added": "Today"
        }
        return leads, stats
    except FileNotFoundError:
        # Return empty data if file not found
        return [], {"total_leads": 0, "common_industry": "None", "latest_added": "None"}
    except Exception as e:
        # Log the error and return empty data
        print(f"Error loading leads: {e}")
        return [], {"total_leads": 0, "common_industry": "None", "latest_added": "Error"}

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/')
def index():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return render_template('base2.html')

@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials

    session["credentials"] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    userinfo_endpoint = requests.get(GOOGLE_DISCOVERY_URL).json()["userinfo_endpoint"]
    response = requests.get(
        userinfo_endpoint,
        headers={'Authorization': f'Bearer {credentials.token}'},
    )
    
    if response.ok:
        user_info = response.json()
        # Record login and get user_id
        user_id = record_login(user_info["email"], user_info.get("name", ""))
        
        session["user"] = {
            "id": user_id,
            "email": user_info["email"],
            "name": user_info.get("name", ""),
            "picture": user_info.get("picture", "")
        }
        
        return redirect(url_for("dashboard"))
    return "Failed to get user info", 400

@app.route('/admin')
@login_required
def admin_dashboard():
    if not is_admin():
        return redirect(url_for('dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT u.id, u.email, u.name, u.created_at, u.last_login, 
               u.subscription_type, u.lead_view_limit,
               COUNT(lv.id) as view_count
        FROM users u
        LEFT JOIN lead_views lv ON u.id = lv.user_id
        GROUP BY u.id
        ORDER BY u.created_at DESC
    """)
    users = cursor.fetchall()
    
    cursor.execute("""
        SELECT u.email, lv.lead_index, lv.viewed_at
        FROM lead_views lv
        JOIN users u ON lv.user_id = u.id
        ORDER BY lv.viewed_at DESC
        LIMIT 100
    """)
    lead_views = cursor.fetchall()
    
    return render_template('admin.html', users=users, lead_views=lead_views)

@app.route('/admin/user/<int:user_id>')
@login_required
def admin_user_detail(user_id):
    if not is_admin():
        return redirect(url_for('dashboard'))
    
    analytics = get_user_analytics(user_id)
    
    return render_template('user_detail.html', analytics=analytics)

@app.route('/admin/update_subscription', methods=['POST'])
@login_required
def admin_update_subscription():
    if not is_admin():
        return redirect(url_for('dashboard'))
    
    user_id = request.form.get('user_id')
    subscription_type = request.form.get('subscription_type')
    view_limit = request.form.get('view_limit')
    
    update_user_subscription(user_id, subscription_type, view_limit)
    flash('User subscription updated successfully')
    
    return redirect(url_for('admin_user_detail', user_id=user_id))

@app.route('/logout')
def logout():
    if "user" in session:
        record_logout(session["user"].get("id"))
    session.clear()
    return redirect(url_for("index"))

@app.route('/dashboard')
@login_required
def dashboard():
    search_query = request.args.get('search', '').lower()
    show_viewed_only = request.args.get('viewed_only', 'false').lower() == 'true'
    
    leads, stats = load_leads('Untitled spreadsheet - CSP_Main sheet.csv')
    
    user_id = session["user"]["id"]
    view_count = get_user_lead_views_count(user_id)
    view_limit = get_user_view_limit(user_id)
    
    # Get list of viewed lead indices for this user
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT DISTINCT lead_index FROM lead_views WHERE user_id = ?", (user_id,))
    viewed_indices = {row[0] for row in cursor.fetchall()}
    
    # Filter leads based on search query and viewed status
    filtered_leads = []
    for lead in leads:
        if show_viewed_only and lead['index'] not in viewed_indices:
            continue
            
        if search_query:
            if search_query not in lead.get('Company Name', '').lower() and \
               search_query not in lead.get('Industry', '').lower():
                continue
                
        filtered_leads.append(lead)
    
    return render_template('index2.html', 
                         leads=filtered_leads,
                         stats=stats,
                         search_query=search_query,
                         user=session["user"],
                         view_count=view_count,
                         view_limit=view_limit,
                         viewed_indices=viewed_indices,
                         show_viewed_only=show_viewed_only)
@app.route('/lead/<int:index>')
@login_required
def lead_profile(index):
    user_id = session["user"]["id"]
    
    # Check if user has already viewed this lead
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id FROM lead_views WHERE user_id = ? AND lead_index = ?", (user_id, index))
    already_viewed = cursor.fetchone() is not None
    
    # Get user's view count and limit
    view_count = get_user_lead_views_count(user_id)
    view_limit = get_user_view_limit(user_id)
    
    # Allow access if either:
    # 1. User hasn't reached their limit, or
    # 2. User has already viewed this lead
    if view_count < view_limit or already_viewed:
        leads, _ = load_leads('Untitled spreadsheet - CSP_Main sheet.csv')
        if leads and 0 <= index < len(leads):
            lead = leads[index]
            # Only record the view if it's the first time viewing
            if not already_viewed:
                record_lead_view(user_id, index)
            return render_template('lead.html', lead=lead, user=session['user'])
        return "Lead not found", 404
    else:
        return redirect(url_for('pricing'))
    
    return redirect(url_for('pricing'))

@app.route('/pricing')
@login_required
def pricing():
    return render_template('pricing.html', user=session['user'])

@app.route('/subscribe', methods=['POST'])
@login_required
def subscribe():
    plan = request.form.get('plan')
    
    # In a real app, you'd process payment here
    # For this demo, we'll just update the user's subscription
    
    user_id = session["user"]["id"]
    
    if plan == 'basic':
        update_user_subscription(user_id, 'basic', 25)
    elif plan == 'pro':
        update_user_subscription(user_id, 'pro', 100)
    elif plan == 'enterprise':
        update_user_subscription(user_id, 'enterprise', 9999)
    
    flash('Subscription updated successfully!')
    return redirect(url_for('dashboard'))

# Analytics routes
@app.route('/analytics')
@login_required
def analytics():
    if not is_admin():
        return redirect(url_for('dashboard'))
    
    db = get_db()
    cursor = db.cursor()
    
    # User growth over time
    cursor.execute("""
        SELECT strftime('%Y-%m', created_at) as month, COUNT(*) as new_users
        FROM users
        GROUP BY month
        ORDER BY month
    """)
    user_growth = cursor.fetchall()
    
    # Most viewed leads
    cursor.execute("""
        SELECT lead_index, COUNT(*) as view_count
        FROM lead_views
        GROUP BY lead_index
        ORDER BY view_count DESC
        LIMIT 10
    """)
    popular_leads = cursor.fetchall()
    
    # Active users by day
    cursor.execute("""
        SELECT strftime('%Y-%m-%d', login_time) as day, COUNT(DISTINCT user_id) as active_users
        FROM user_sessions
        GROUP BY day
        ORDER BY day DESC
        LIMIT 30
    """)
    active_users = cursor.fetchall()
    
    return render_template('analytics.html', 
                          user_growth=user_growth, 
                          popular_leads=popular_leads,
                          active_users=active_users)

# Initialize the database at startup
init_db()
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
