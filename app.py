from flask import Flask, render_template, request, redirect, url_for, session, flash
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
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace with a secure secret key

# PostgreSQL Database Configuration
DATABASE_URL = "postgresql://neondb_owner:npg_sjMR1fNZUPO6@ep-still-pine-a8lzrh1e-pooler.eastus2.azure.neon.tech/neondb?sslmode=require"
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    name = db.Column(db.String(120))
    created_at = db.Column(db.DateTime, default=func.now())
    last_login = db.Column(db.DateTime)
    subscription_type = db.Column(db.String(20), default='free')
    lead_view_limit = db.Column(db.Integer, default=5)
    
    lead_views = db.relationship('LeadView', backref='user', lazy=True)
    sessions = db.relationship('UserSession', backref='user', lazy=True)

class LeadView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    lead_index = db.Column(db.Integer, nullable=False)
    viewed_at = db.Column(db.DateTime, default=func.now())

class UserSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    login_time = db.Column(db.DateTime, default=func.now())
    logout_time = db.Column(db.DateTime)

class LeadData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(200))
    industry = db.Column(db.String(100))
    description = db.Column(db.Text)

# Google OAuth2 configuration
GOOGLE_CLIENT_ID = "your-client-id"  # Replace with your actual client ID
GOOGLE_CLIENT_SECRET = "your-client-secret"  # Replace with your actual client secret
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# OAuth2 configuration
client_secrets_file = os.path.join(os.path.dirname(__file__), "cred.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "openid"
    ],
    redirect_uri="https://foundersmail.vercel.app/callback"
)

DEFAULT_VIEW_LIMIT = 5

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function



def record_login(email, name):
    now = datetime.utcnow()
    user = User.query.filter_by(email=email).first()
    
    if user:
        user.last_login = now
        user_id = user.id
    else:
        user = User(email=email, name=name, last_login=now)
        db.session.add(user)
        db.session.flush()
        user_id = user.id
    
    session = UserSession(user_id=user_id)
    db.session.add(session)
    db.session.commit()
    
    return user_id

def record_logout(user_id):
    if user_id:
        session = UserSession.query.filter_by(
            user_id=user_id, 
            logout_time=None
        ).order_by(UserSession.login_time.desc()).first()
        
        if session:
            session.logout_time = datetime.utcnow()
            db.session.commit()

def record_lead_view(user_id, lead_index):
    lead_view = LeadView(user_id=user_id, lead_index=lead_index)
    db.session.add(lead_view)
    db.session.commit()

def get_user_lead_views_count(user_id):
    return LeadView.query.filter_by(user_id=user_id).count()

def get_user_view_limit(user_id):
    user = User.query.get(user_id)
    return user.lead_view_limit if user else DEFAULT_VIEW_LIMIT

def update_user_subscription(user_id, subscription_type, view_limit):
    user = User.query.get(user_id)
    if user:
        user.subscription_type = subscription_type
        user.lead_view_limit = view_limit
        db.session.commit()

def get_user_analytics(user_id):
    user = User.query.get(user_id)
    if not user:
        return None
    
    sessions = UserSession.query.filter_by(user_id=user_id).order_by(UserSession.login_time.desc()).all()
    lead_views = db.session.query(
        LeadView, LeadData.company_name
    ).outerjoin(
        LeadData, LeadView.lead_index == LeadData.id
    ).filter(
        LeadView.user_id == user_id
    ).order_by(
        LeadView.viewed_at.desc()
    ).all()
    
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
        
        # Clear existing data
        LeadData.query.delete()
        
        # Insert new data
        for idx, row in df.iterrows():
            lead = LeadData(
                id=idx,
                company_name=row['Company Name'],
                industry=row['Industry'],
                description=row['Description']
            )
            db.session.add(lead)
        
        db.session.commit()
        
        leads = df.to_dict(orient='records')
        for i, lead in enumerate(leads):
            lead['index'] = i
        
        stats = {
            "total_leads": len(leads),
            "common_industry": max(set(df['Industry']), key=list(df['Industry']).count) if not df.empty else "None",
            "latest_added": "Today"
        }
        return leads, stats
    except Exception as e:
        print(f"Error loading leads: {e}")
        return [], {"total_leads": 0, "common_industry": "None", "latest_added": "Error"}

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
    
    try:
        # Get users with their view counts and latest activity
        users_data = db.session.query(
            User,
            func.count(LeadView.id).label('view_count'),
            func.max(UserSession.login_time).label('last_activity')
        ).outerjoin(LeadView).outerjoin(UserSession).group_by(User.id).order_by(User.created_at.desc()).all()

        # Format user data for template
        users = []
        for user, view_count, last_activity in users_data:
            users.append({
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'created_at': user.created_at,
                'last_login': user.last_login,
                'subscription_type': user.subscription_type,
                'lead_view_limit': user.lead_view_limit,
                'view_count': view_count,
                'last_activity': last_activity
            })

        # Get recent lead views with user information
        lead_views = db.session.query(
            User.email,
            User.name,
            LeadView.lead_index,
            LeadView.viewed_at,
            LeadData.company_name
        ).join(
            User, User.id == LeadView.user_id
        ).outerjoin(
            LeadData, LeadData.id == LeadView.lead_index
        ).order_by(
            LeadView.viewed_at.desc()
        ).limit(100).all()

        # Format lead views for template
        formatted_lead_views = []
        for view in lead_views:
            formatted_lead_views.append({
                'email': view.email,
                'user_name': view.name,
                'lead_index': view.lead_index,
                'viewed_at': view.viewed_at,
                'company_name': view.company_name or 'Unknown Company'
            })

        # Get summary statistics
        stats = {
            'total_users': len(users),
            'total_views': db.session.query(func.count(LeadView.id)).scalar() or 0,
            'active_users_today': db.session.query(func.count(func.distinct(UserSession.user_id))).filter(
                func.date(UserSession.login_time) == func.current_date()
            ).scalar() or 0
        }

        return render_template(
            'admin.html',
            users=users,
            lead_views=formatted_lead_views,
            stats=stats
        )

    except Exception as e:
        print(f"Admin dashboard error: {e}")
        db.session.rollback()
        flash('Error loading admin dashboard', 'error')
        return redirect(url_for('dashboard'))

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
    
    user_id = request.form.get('user_id', type=int)
    subscription_type = request.form.get('subscription_type')
    view_limit = request.form.get('view_limit', type=int)
    
    if user_id and subscription_type and view_limit:
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
    
    viewed_leads = LeadView.query.filter_by(user_id=user_id).with_entities(LeadView.lead_index).all()
    viewed_indices = {view.lead_index for view in viewed_leads}
    
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
    
    already_viewed = LeadView.query.filter_by(user_id=user_id, lead_index=index).first() is not None
    view_count = get_user_lead_views_count(user_id)
    view_limit = get_user_view_limit(user_id)
    
    if view_count < view_limit or already_viewed:
        leads, _ = load_leads('Untitled spreadsheet - CSP_Main sheet.csv')
        if leads and 0 <= index < len(leads):
            lead = leads[index]
            if not already_viewed:
                record_lead_view(user_id, index)
            return render_template('lead.html', lead=lead, user=session['user'])
        return "Lead not found", 404
    
    return redirect(url_for('pricing'))

@app.route('/pricing')
@login_required
def pricing():
    return render_template('pricing.html', user=session['user'])

@app.route('/subscribe', methods=['POST'])
@login_required
def subscribe():
    plan = request.form.get('plan')
    user_id = session["user"]["id"]
    
    plan_limits = {
        'basic': 25,
        'pro': 100,
        'enterprise': 9999
    }
    
    if plan in plan_limits:
        update_user_subscription(user_id, plan, plan_limits[plan])
        flash('Subscription updated successfully!')
    
    return redirect(url_for('dashboard'))

@app.route('/analytics')
@login_required
def analytics():
    if not is_admin():
        return redirect(url_for('dashboard'))
    
    # User growth over time
    user_growth = db.session.query(
        func.date_trunc('month', User.created_at).label('month'),
        func.count(User.id).label('new_users')
    ).group_by('month').order_by('month').all()
    
    # Most viewed leads
    popular_leads = db.session.query(
        LeadView.lead_index,
        func.count(LeadView.id).label('view_count')
    ).group_by(LeadView.lead_index).order_by(func.count(LeadView.id).desc()).limit(10).all()
    # Active users by day
    active_users = db.session.query(
        func.date_trunc('day', UserSession.login_time).label('day'),
        func.count(func.distinct(UserSession.user_id)).label('active_users')
    ).group_by('day').order_by('day').limit(30).all()
    
    return render_template('analytics.html', 
                          user_growth=user_growth, 
                          popular_leads=popular_leads,
                          active_users=active_users)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500
def is_admin():
    # For demo purposes, you might want to hardcode some admin emails
    admin_emails = ['odelapradeep12@gmail.com', 'your_email@gmail.com']
    if session["user"]["email"] in admin_emails:
        return True
    return False
# Initialize database tables
def init_db():
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Check if admin user exists, if not create one
        admin_email = 'odelapradeep12@gmail.com'
        admin = User.query.filter_by(email=admin_email).first()
        if not admin:
            admin = User(
                email=admin_email,
                name='Admin',
                subscription_type='enterprise',
                lead_view_limit=9999
            )
            db.session.add(admin)
            db.session.commit()
init_db()
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
