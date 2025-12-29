import os
import random
import re
from datetime import datetime, timedelta, date
from functools import wraps


from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# ---- Load .env (if present) ----
load_dotenv()
print("Loaded ADMIN_EMAIL:", os.getenv('ADMIN_EMAIL'))
print("Loaded ADMIN_PASSWORD:", os.getenv('ADMIN_PASSWORD'))

# -------------------- APP SETUP --------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-me')

# -------------------- PATHS --------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(BASE_DIR, 'instance', 'jobportal.db')
os.makedirs(os.path.dirname(db_path), exist_ok=True)

# -------------------- DATABASE --------------------
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',  # Supabase PostgreSQL
    f'sqlite:///{db_path}'  # fallback (local only)
)

# Prevent dropped connections (IMPORTANT for Supabase)
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    "pool_pre_ping": True
}

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# ================== ROLE–PERMISSION MAPPING ==================
admin_role_permissions = db.Table(
    'admin_role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('admin_roles.id')),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id'))
)

# -------------------- MAIL --------------------



app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER", "smtp.gmail.com")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT", 587))
app.config['MAIL_USE_TLS'] = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
app.config['MAIL_USE_SSL'] = False

app.config['MAIL_USERNAME'] = os.getenv("jobsour997@gmail.com")
app.config['MAIL_PASSWORD'] = os.getenv("iiprvglsjgieiiny")
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

mail = Mail(app)
# -------------------- UPLOADS --------------------
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'resumes')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB

ID_PROOFS_FOLDER = os.path.join(BASE_DIR, 'static', 'id_proofs')
os.makedirs(ID_PROOFS_FOLDER, exist_ok=True)
app.config['ID_PROOFS_FOLDER'] = ID_PROOFS_FOLDER

ALLOWED_EXT = {'pdf'}
ALLOWED_ID_EXT = {'png', 'jpg', 'jpeg', 'pdf'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

def allowed_id_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_ID_EXT

# -------------------- AUTH --------------------
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# -------------------- HELPERS --------------------
def slugify(text):
    text = text.lower()
    text = text.replace("/", "-")
    text = text.replace("&", "and")
    text = re.sub(r'[^a-z0-9\- ]', '', text)
    return text.replace(" ", "-")

app.jinja_env.globals.update(slugify=slugify)

# OTP store: in-memory — for production, persist or use Redis
otp_store = {}  # { email: {'otp': '123456', 'expires': datetime } }

def send_email_otp_for(email):
    """Send OTP to email. Return (True, None) on success, else (False, error)."""
    otp = str(random.randint(100000, 999999))
    otp_store[email] = {
        'otp': otp,
        'expires': datetime.utcnow() + timedelta(minutes=10)
    }

    html = f"""
    <div style="font-family:Arial, sans-serif; padding:20px;">
      <h3>Our Jobs — OTP</h3>
      <p>Your OTP is: <strong style="font-size:22px">{otp}</strong></p>
      <p>This code is valid for 10 minutes.</p>
    </div>
    """

    try:
        msg = Message(
            "Your OTP — OurJobs",
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[email]
        )
        msg.html = html
        mail.send(msg)

        app.logger.info("OTP sent to %s", email)
        print("DEV OTP for", email, ":", otp)
        return True, None

    except Exception as e:
        app.logger.exception("Error sending OTP")
        print("DEV OTP for", email, ":", otp)
        return False, str(e)
def check_otp(email, code):
    """Return True if OTP valid for email."""
    entry = otp_store.get(email)
    if not entry:
        return False
    if datetime.utcnow() > entry['expires']:
        otp_store.pop(email, None)
        return False
    return str(entry['otp']) == str(code)

def seed_admin_roles():
    roles = [
        ("User Manager", "Manage users"),
        ("Job Manager", "Approve & reject jobs"),
        ("Support Manager", "Handle support messages")
    ]

    for name, desc in roles:
        if not AdminRole.query.filter_by(name=name).first():
            db.session.add(AdminRole(name=name, description=desc))

    db.session.commit()
def send_job_approved_email(job, employer):
    try:
        msg = Message(
            subject="🎉 Your job has been approved | OurJobs",
            recipients=[employer.email]
        )

        msg.html = f"""
        <div style="font-family:Arial,sans-serif; padding:20px;">
            <h2 style="color:green;">🎉 Congratulations!</h2>

            <p>Hello <strong>{employer.name or 'Employer'}</strong>,</p>

            <p>Your job <strong>{job.title}</strong> has been <b>approved</b> by our admin team.</p>

            <p>✅ Your job is now <strong>LIVE</strong> and visible to job seekers.</p>

            <hr>
            <p>
              📌 <b>Job Title:</b> {job.title}<br>
              📍 <b>Location:</b> {job.location}<br>
              🕒 <b>Status:</b> Approved
            </p>

            <p>We wish you the best in finding the right candidate.</p>

            <p>Best regards,<br>
            <strong>OurJobs Team</strong></p>
        </div>
        """

        mail.send(msg)

    except Exception as e:
        print("Approval email error:", e)

def send_job_rejected_email(job, employer, reason):
    try:
        msg = Message(
            subject="❌ Job rejected | OurJobs",
            recipients=[employer.email]
        )

        msg.html = f"""
        <div style="font-family:Arial,sans-serif; padding:20px;">
            <h2 style="color:red;">Job Rejected</h2>

            <p>Hello <strong>{employer.name or 'Employer'}</strong>,</p>

            <p>We regret to inform you that your job <strong>{job.title}</strong> has been <b>rejected</b>.</p>

            <p><strong>Reason for rejection:</strong></p>
            <blockquote style="background:#f8d7da; padding:12px; border-left:4px solid red;">
                {reason}
            </blockquote>

            <p>You may correct the issue and post the job again.</p>

            <p>If you believe this is a mistake, feel free to contact support.</p>

            <p>Regards,<br>
            <strong>OurJobs Team</strong></p>
        </div>
        """

        mail.send(msg)

    except Exception as e:
        print("Rejection email error:", e)

def seed_permissions():
    permissions = [
        ("view_users", "View users"),
        ("delete_users", "Delete users"),
        ("approve_jobs", "Approve jobs"),
        ("reject_jobs", "Reject jobs"),
        ("view_jobs", "View jobs"),
        ("resolve_support", "Resolve support tickets"),
    ]

    for code, desc in permissions:
        if not AdminPermission.query.filter_by(code=code).first():
            db.session.add(AdminPermission(code=code, description=desc))

    db.session.commit()

def send_job_submission_email(job, employer):
    try:
        msg = Message(
            subject="Your job has been submitted for verification | OurJobs",
            recipients=[employer.email]
        )

        msg.html = f"""
        <div style="font-family:Arial,sans-serif; padding:20px;">
            <h2>Thank you for posting a job!</h2>

            <p>Hello <strong>{employer.name or 'Employer'}</strong>,</p>

            <p>Your job <strong>{job.title}</strong> has been successfully submitted on <b>OurJobs</b>.</p>

            <p>🔍 Our admin team will verify your job shortly.</p>
            <p>⏳ Verification usually takes a short time.</p>

            <hr>
            <p>
              📌 <b>Job Title:</b> {job.title}<br>
              📍 <b>Location:</b> {job.location}<br>
              🕒 <b>Status:</b> Pending Verification
            </p>

            <p>Thank you for choosing <b>OurJobs</b>.</p>

            <p>Best regards,<br>
            <strong>OurJobs Team</strong></p>
        </div>
        """

        mail.send(msg)

    except Exception as e:
        print("Job submission email error:", e)

def permission_required(permission_code):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):

            # 🔐 Admin must be logged in
            if not session.get('admin_logged_in'):
                flash("Admin login required.", "warning")
                return redirect(url_for('admin_login'))

            admin = User.query.get(session.get('admin_id'))

            if not admin:
                flash("Admin not found.", "danger")
                return redirect(url_for('admin_login'))

            # ⭐ Super Admin can access everything
            if admin.is_super_admin:
                return func(*args, **kwargs)

            # ❌ Permission check
            if not admin.has_permission(permission_code):
                flash("Permission denied.", "danger")
                return redirect(url_for('admin_dashboard'))

            return func(*args, **kwargs)

        return wrapper
    return decorator

def assign_permissions():
    role_map = {
        "User Manager": ["view_users", "delete_users"],
        "Job Manager": ["view_jobs", "approve_jobs", "reject_jobs"],
        "Support Manager": ["resolve_support"]
    }

    for role_name, perms in role_map.items():
        role = AdminRole.query.filter_by(name=role_name).first()
        for p in perms:
            perm = AdminPermission.query.filter_by(code=p).first()
            exists = AdminRolePermission.query.filter_by(
                role_id=role.id,
                permission_id=perm.id
            ).first()
            if not exists:
                db.session.add(AdminRolePermission(
                    role_id=role.id,
                    permission_id=perm.id
                ))

    db.session.commit()



# -------------------- MODELS --------------------
class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)

    # ---------------- BASIC INFO ----------------
    name = db.Column(db.String(120), nullable=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=True)

    # ---------------- EXISTING FLAGS ----------------
    is_employer = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_super_admin = db.Column(db.Boolean, default=False)

    # ✅ ACTIVE / DEACTIVE (VERY IMPORTANT)
    is_active = db.Column(db.Boolean, default=True)

    # ---------------- ROLE SYSTEM ----------------
    role = db.Column(db.String(20), default="jobseeker")

    # ---------------- SUB-ADMIN SYSTEM ----------------
    admin_role_id = db.Column(db.Integer, db.ForeignKey('admin_roles.id'))
    admin_role = db.relationship('AdminRole', backref='admins')

    # ---------------- PROFILE INFO ----------------
    phone = db.Column(db.String(20))
    dob = db.Column(db.Date)
    gender = db.Column(db.String(10))
    address = db.Column(db.Text)

    gov_id_type = db.Column(db.String(20))
    gov_id_number = db.Column(db.String(50))
    gov_id_file = db.Column(db.String(200))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    # ---------------- RELATIONSHIPS ----------------
    applications = db.relationship('Application', backref='applicant', lazy=True)
    jobs = db.relationship('Job', backref='poster', lazy=True)

    # ---------------- METHODS ----------------
    def set_password(self, pw):
        self.password_hash = bcrypt.generate_password_hash(pw).decode('utf-8')

    def check_password(self, pw):
        if not self.password_hash:
            return False
        return bcrypt.check_password_hash(self.password_hash, pw)

    def has_permission(self, permission_name):
        if self.is_super_admin:
            return True
        if not self.admin_role:
            return False
        return any(p.code == permission_name for p in self.admin_role.permissions)

class EmployerProfile(db.Model):
    _tablename_ = 'employer_profile'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_name = db.Column(db.String(200), nullable=False)
    contact_number = db.Column(db.String(30))
    location = db.Column(db.String(200))
    description = db.Column(db.Text)
    company_logo = db.Column(db.String(300))

    user = db.relationship('User', backref=db.backref('employer_profile', uselist=False))

class Job(db.Model):
    _tablename_ = 'job'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(150))
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(150))
    salary = db.Column(db.String(80))
    job_type = db.Column(db.String(50))  # 'small' or 'large'

    qualification = db.Column(db.String(200))
    experience = db.Column(db.String(200))
    benefits = db.Column(db.Text)

    company_logo = db.Column(db.String(300))
    posted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    status = db.Column(db.String(20), default='Pending')  # Pending / Approved / Rejected

    # small job fields
    salary_type = db.Column(db.String(50))
    workplace_type = db.Column(db.String(50))
    full_address = db.Column(db.Text)
    google_map_link = db.Column(db.String(250))
    pincode = db.Column(db.String(10))
    risk_level = db.Column(db.String(50))
    tools_provided = db.Column(db.Boolean, default=False)
    food_provided = db.Column(db.Boolean, default=False)
    stay_provided = db.Column(db.Boolean, default=False)

    # large job fields (company)
    company_name = db.Column(db.String(150))
    company_address = db.Column(db.Text)
    company_website = db.Column(db.String(150))
    company_email = db.Column(db.String(120))
    company_phone = db.Column(db.String(20))

    # new job metadata
    job_start_date = db.Column(db.Date, nullable=True)
    job_deadline = db.Column(db.Date, nullable=True)
    age_requirement_min = db.Column(db.Integer, nullable=True)
    age_requirement_max = db.Column(db.Integer, nullable=True)

    applications = db.relationship('Application', backref='job', lazy=True)

class Application(db.Model):
    __tablename__ = 'application'

    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20))
    age = db.Column(db.Integer)
    experience = db.Column(db.Float)
    cover_letter = db.Column(db.Text)
    resume = db.Column(db.String(200))

    status = db.Column(db.String(20), default='Pending')  # Pending / Viewed / Selected / Rejected
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)

class SupportMessage(db.Model):
    _tablename_ = 'support_message'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(200), nullable=True)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Admin(db.Model):
    _tablename_ = 'admin'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(300), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)



class AdminPermission(db.Model):
    __tablename__ = 'admin_permissions'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(200))



class AdminActivityLog(db.Model):
    __tablename__ = 'admin_activity_logs'

    id = db.Column(db.Integer, primary_key=True)

    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    admin = db.relationship('User')

    action = db.Column(db.String(200))
    target_type = db.Column(db.String(50))  # user / job / support
    target_id = db.Column(db.Integer)

    reason = db.Column(db.Text)
    ip_address = db.Column(db.String(45))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Permission(db.Model):
    __tablename__ = 'permissions'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(200))

class AdminRole(db.Model):
    __tablename__ = 'admin_roles'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    permissions = db.relationship(
        'Permission',
        secondary=admin_role_permissions,
        backref='roles'
    )


# -------------------- LOGIN LOADER --------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------- HELPERS / MIDDLEWARE --------------------
def ensure_admin_exists():
    admin_email = os.getenv('ADMIN_EMAIL')
    admin_password = os.getenv('ADMIN_PASSWORD')

    if not admin_email or not admin_password:
        return

    admin = User.query.filter_by(email=admin_email, is_admin=True).first()

    if not admin:
        admin = User(
            name="Admin",
            email=admin_email,
            is_admin=True,
            role="admin"
        )
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin created:", admin_email)

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated and current_user.is_admin:
            return f(*args, **kwargs)
        if session.get('admin_logged_in') or session.get('admin_id'):
            return f(*args, **kwargs)
        flash("Admin access required.", "danger")
        return redirect(url_for('admin_login'))
    return wrapper
# -------------------- ROUTES --------------------

@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    title_q = request.args.get('title', '').strip()
    location_q = request.args.get('location', '').strip()
    jobs_q = Job.query.filter_by(status='Approved')
    if title_q:
        jobs_q = jobs_q.filter(Job.title.ilike(f"%{title_q}%"))
    if location_q:
        jobs_q = jobs_q.filter(Job.location.ilike(f"%{location_q}%"))
    jobs = jobs_q.order_by(Job.created_at.desc()).paginate(page=page, per_page=8, error_out=False)
    categories = [c[0] for c in db.session.query(Job.category).distinct().all() if c[0]]
    return render_template('index.html', jobs=jobs, title=title_q, location=location_q, categories=categories)

@app.route('/jobs')
def job_list():
    return index()

# -------------------- CREATE SUB ADMIN --------------------
@app.route('/admin/create-subadmin', methods=['GET', 'POST'])
def admin_create_subadmin():
    print("🔥 admin_create_subadmin HIT:", request.method)

    # 🔐 Admin must be logged in
    if not session.get('admin_logged_in'):
        flash("Admin login required.", "warning")
        return redirect(url_for('admin_login'))

    current_admin = User.query.get(session.get('admin_id'))

    # 🛑 Only Super Admin
    if not current_admin or not current_admin.is_super_admin:
        flash("Only Super Admin can create sub-admins.", "danger")
        return redirect(url_for('admin_dashboard'))

    # 🔽 Roles for dropdown (optional use in template later)
    admin_roles = AdminRole.query.all()

    if request.method == 'POST':
        print("🔥 POST DATA:", request.form)

        # ✅ SAFE GET (no crash)
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        role_code = request.form.get('admin_role')

        # ❌ Validation
        if not name or not email or not password or not role_code:
            flash("All fields are required.", "danger")
            return redirect(url_for('admin_create_subadmin'))

        # ❌ Duplicate email
        if User.query.filter_by(email=email).first():
            flash("Email already exists.", "danger")
            return redirect(url_for('admin_create_subadmin'))

        # 🔁 Map dropdown → DB role
        role_map = {
            "job_admin": "Job Admin",
            "user_admin": "User Admin",
            "support_admin": "Support Admin"
        }

        role_name = role_map.get(role_code)
        if not role_name:
            flash("Invalid admin role.", "danger")
            return redirect(url_for('admin_create_subadmin'))

        admin_role = AdminRole.query.filter_by(name=role_name).first()
        if not admin_role:
            flash("Admin role not found in database.", "danger")
            return redirect(url_for('admin_create_subadmin'))

        # ✅ Create sub-admin
        subadmin = User(
            name=name,
            email=email,
            role='admin',
            is_admin=True,
            is_super_admin=False,
            is_active=True,
            admin_role_id=admin_role.id
        )
        subadmin.set_password(password)

        db.session.add(subadmin)
        db.session.commit()

        # 📝 Activity log
        log = AdminActivityLog(
            admin_id=current_admin.id,
            action=f"Created Sub Admin ({role_name})",
            target_type="user",
            target_id=subadmin.id,
            ip_address=request.remote_addr
        )
        db.session.add(log)
        db.session.commit()

        flash(f"{role_name} created successfully.", "success")
        return redirect(url_for('admin_dashboard'))

    # GET request
    return render_template(
        'admin_create_subadmin.html',
        admin_roles=admin_roles
    )

# -------------------- AUTH ROUTES --------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    # This route now collects full profile; registration will use OTP
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        role = request.form.get('role', 'jobseeker')  # jobseeker|employer
        phone = request.form.get('phone')
        gender = request.form.get('gender')
        dob_str = request.form.get('dob')
        address = request.form.get('address')

        gov_id_type = request.form.get('gov_id_type')
        gov_id_number = request.form.get('gov_id_number')
        gov_file = request.files.get('gov_id_file')

        # validation
        if not email or not password:
            flash("Email and password required", "danger")
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash("Email already registered. Please login.", "warning")
            return redirect(url_for('login'))

        # Save gov id file temporarily with a TEMP_ prefix; only commit user after OTP verified
        saved_file = None
        if gov_file and gov_file.filename:
            if allowed_id_file(gov_file.filename):
                safe = secure_filename(f"TEMP_{int(datetime.utcnow().timestamp())}_{gov_file.filename}")
                gov_file.save(os.path.join(app.config['ID_PROOFS_FOLDER'], safe))
                saved_file = safe
            else:
                flash("ID proof must be JPG/PNG/PDF", "danger")
                return render_template('register.html')

        # store pending user in session
        session['pending_user'] = {
            'name': name,
            'email': email,
            'password': password,
            'role': role,
            'phone': phone,
            'gender': gender,
            'dob': dob_str,
            'address': address,
            'gov_id_type': gov_id_type,
            'gov_id_number': gov_id_number,
            'gov_id_file': saved_file
        }

        ok, info = send_email_otp_for(email)
        if not ok:
            flash(f"Error sending OTP: {info}", "danger")
            return render_template('register.html')
        flash("OTP sent to your email. Enter it to complete registration.", "info")
        return redirect(url_for('verify_otp_register'))
    return render_template('register.html')

@app.route('/verify-otp-register', methods=['GET', 'POST'])
def verify_otp_register():
    pending = session.get('pending_user')
    if not pending:
        flash("No pending registration found; start again.", "warning")
        return redirect(url_for('register'))
    if request.method == 'POST':
        code = request.form.get('otp', '').strip()
        if check_otp(pending['email'], code):
            # move TEMP file to final (if exists)
            final_file = None
            if pending.get('gov_id_file'):
                tmp = pending['gov_id_file']
                final_name = tmp.replace("TEMP_", "")
                try:
                    os.rename(os.path.join(app.config['ID_PROOFS_FOLDER'], tmp),
                              os.path.join(app.config['ID_PROOFS_FOLDER'], final_name))
                    final_file = final_name
                except Exception:
                    # fallback use tmp (exists)
                    final_file = tmp

            user = User(
                name=pending.get('name'),
                email=pending.get('email'),
                phone=pending.get('phone'),
                gender=pending.get('gender'),
                dob=datetime.strptime(pending['dob'], '%Y-%m-%d').date() if pending.get('dob') else None,
                address=pending.get('address'),
                role=pending.get('role', 'jobseeker'),
                gov_id_type=pending.get('gov_id_type'),
                gov_id_number=pending.get('gov_id_number'),
                gov_id_file=final_file
            )
            user.set_password(pending.get('password'))
            # Make employer boolean consistent
            if user.role == 'employer':
                user.is_employer = True
            db.session.add(user)
            db.session.commit()
            # clean session / otp
            session.pop('pending_user', None)
            otp_store.pop(user.email, None)
            flash("Registration successful. Log in now.", "success")
            return redirect(url_for('login'))
        flash("Invalid or expired OTP.", "danger")
    return render_template('verify_otp.html', email=pending.get('email'), action='register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        # env admin check
        env_admin = os.getenv('ADMIN_EMAIL')
        env_pass = os.getenv('ADMIN_PASSWORD')
        if env_admin and identifier == env_admin and password == env_pass:
            session['admin_logged_in'] = True
            flash("Logged in as environment admin.", "success")
            return redirect(url_for('admin_dashboard'))

        user = User.query.filter_by(email=identifier).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Login successful.", "success")
            return redirect(url_for('index'))
        flash("Invalid credentials.", "danger")
    return render_template('login.html')

@app.route('/send-otp', methods=['GET', 'POST'])
def send_otp():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()

        if not email:
            flash("Enter email.", "warning")
            return render_template('send_otp.html')

        # 🔒 BLOCK UNREGISTERED USERS HERE
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Email not registered. Please register first.", "danger")
            return redirect(url_for('register'))

        ok, info = send_email_otp_for(email)
        if not ok:
            flash(f"Error sending OTP: {info}", "danger")
            return render_template('send_otp.html')

        session['otp_email'] = email
        flash("OTP sent. Check your email.", "info")
        return redirect(url_for('verify_otp_login'))

    return render_template('send_otp.html')
@app.route('/verify-otp-login', methods=['GET', 'POST'])
def verify_otp_login():
    email = session.get('otp_email')

    if not email:
        flash("Start by entering email to receive OTP.", "warning")
        return redirect(url_for('send_otp'))

    if request.method == 'POST':
        code = request.form.get('otp', '').strip()

        if not check_otp(email, code):
            flash("Invalid or expired OTP.", "danger")
            return render_template('verify_otp.html', email=email, action='login')

        # ✅ ONLY LOGIN EXISTING USER
        user = User.query.filter_by(email=email).first()

        if not user:
            flash("No account found. Please register first.", "warning")
            otp_store.pop(email, None)
            session.pop('otp_email', None)
            return redirect(url_for('register'))

        login_user(user)
        otp_store.pop(email, None)
        session.pop('otp_email', None)

        flash("Logged in successfully.", "success")
        return redirect(url_for('index'))

    return render_template('verify_otp.html', email=email, action='login')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('admin_logged_in', None)
    session.pop('admin_id', None)
    flash("Logged out.", "info")
    return redirect(url_for('index'))
# -------------------- PROFILE ROUTES --------------------
@app.route('/create_profile', methods=['GET', 'POST'])
@login_required
def create_profile():
    # Employer-only profile (save company info + employer_profile)
    if request.method == 'POST':
        company_name = request.form.get('company_name')
        contact = request.form.get('contact_number')
        location = request.form.get('location')
        description = request.form.get('description')
        logo = request.files.get('company_logo')
        logo_filename = None
        if logo and logo.filename:
            logo_filename = secure_filename(f"{int(datetime.utcnow().timestamp())}_{logo.filename}")
            logo.save(os.path.join(app.config['UPLOAD_FOLDER'], logo_filename))
        # set user as employer
        current_user.is_employer = True
        current_user.role = 'employer'
        profile = EmployerProfile(user_id=current_user.id, company_name=company_name,
                                  contact_number=contact, location=location,
                                  description=description, company_logo=logo_filename)
        db.session.add(profile)
        db.session.commit()
        flash("Profile saved. You can now post jobs.", "success")
        return redirect(url_for('post_job'))
    return render_template('create_profile.html')

@app.route('/profile')
@login_required
def profile():
    user = current_user
    is_employer = user.is_employer or user.role == 'employer'

    # ---------------- JOB SEEKER PROFILE ----------------
    if not is_employer:
        applications = Application.query.filter_by(
            user_id=user.id
        ).order_by(Application.applied_at.desc()).all()

        return render_template(
            'profile.html',
            user=user,
            applications=applications,
            is_employer=False
        )

    # ---------------- EMPLOYER PROFILE ----------------
    jobs = Job.query.filter_by(
        posted_by=user.id
    ).order_by(Job.created_at.desc()).all()

    applicants = {}
    for job in jobs:
        applicants[job.id] = Application.query.filter_by(
            job_id=job.id
        ).order_by(Application.applied_at.desc()).all()

    return render_template(
        'employer_profile.html',
        user=user,
        jobs=jobs,
        applicants=applicants,
        is_employer=True
    )

    # ===================== JOBSEEKER VIEW =====================
    if not is_employer:
        applications = Application.query.filter_by(
            user_id=user.id
        ).order_by(Application.applied_at.desc()).all()

        return render_template(
            'profile.html',
            user=user,
            applications=applications,
            is_employer=False
        )

    # ===================== EMPLOYER VIEW =====================
    posted_jobs = Job.query.filter_by(posted_by=user.id).order_by(Job.created_at.desc()).all()

    # Build required format: { job_id : [list of applications] }
    applicants = {}
    for job in posted_jobs:
        applicants[job.id] = Application.query.filter_by(job_id=job.id).all()

    return render_template(
        'employer_profile.html',
        user=user,
        jobs=posted_jobs,
        applicants=applicants,
        is_employer=True
    )

# -------------------- JOB POSTING --------------------
@app.route('/post_job')
@login_required
def post_job():
    if not (current_user.is_employer or current_user.role == 'employer' or current_user.employer_profile):
        flash("Create employer profile first.", "warning")
        return redirect(url_for('create_profile'))
    return render_template('select_job_type.html')

@app.route('/post_job/small', methods=['GET', 'POST'])
@login_required
def post_job_small():
    if request.method == 'POST':
        title = request.form.get('title')
        category = request.form.get('category')
        description = request.form.get('description')
        location = request.form.get('location')
        salary = request.form.get('salary')
        # small-job extras
        salary_type = request.form.get('salary_type')
        workplace_type = request.form.get('workplace_type')
        full_address = request.form.get('full_address')
        google_map_link = request.form.get('google_map_link')
        pincode = request.form.get('pincode')
        risk_level = request.form.get('risk_level')
        tools_provided = bool(request.form.get('tools_provided'))
        food_provided = bool(request.form.get('food_provided'))
        stay_provided = bool(request.form.get('stay_provided'))
        employer_profile = current_user.employer_profile
        company_logo = employer_profile.company_logo if employer_profile else None
        # optional job dates & ages
        job_start_date_str = request.form.get('job_start_date')
        job_deadline_str = request.form.get('job_deadline')
        age_min = request.form.get('age_min')
        age_max = request.form.get('age_max')
        job_start_date = datetime.strptime(job_start_date_str, '%Y-%m-%d').date() if job_start_date_str else None
        job_deadline = datetime.strptime(job_deadline_str, '%Y-%m-%d').date() if job_deadline_str else None
        job = Job(
            title=title,
            category=category,
            description=description,
            location=location,
            salary=salary,
            salary_type=salary_type,
            workplace_type=workplace_type,
            full_address=full_address,
            google_map_link=google_map_link,
            pincode=pincode,
            risk_level=risk_level,
            tools_provided=tools_provided,
            food_provided=food_provided,
            stay_provided=stay_provided,
            job_type='small',
            posted_by=current_user.id,
            company_logo=company_logo,
            status='Pending',
            job_start_date=job_start_date,
            job_deadline=job_deadline,
            age_requirement_min=int(age_min) if age_min else None,
            age_requirement_max=int(age_max) if age_max else None
        )
        db.session.add(job)
        db.session.commit()
        # 📧 Send email to employer
        send_job_submission_email(job, current_user)
        flash("Small job submitted for admin review.", "info")
        return redirect(url_for('index'))
    return render_template('post_job_small.html')

@app.route('/post_job/large', methods=['GET', 'POST'])
@login_required
def post_job_large():
    if request.method == 'POST':
        title = request.form.get('title')
        category = request.form.get('category')
        description = request.form.get('description')
        location = request.form.get('location')
        salary = request.form.get('salary')
        qualification = request.form.get('qualification')
        experience = request.form.get('experience')
        benefits = request.form.get('benefits')
        company_name = request.form.get('company_name')
        company_address = request.form.get('company_address')
        company_website = request.form.get('company_website')
        company_email = request.form.get('company_email')
        company_phone = request.form.get('company_phone')
        employer_profile = current_user.employer_profile
        company_logo = employer_profile.company_logo if employer_profile else None

        job_start_date_str = request.form.get('job_start_date')
        job_deadline_str = request.form.get('job_deadline')
        age_min = request.form.get('age_min')
        age_max = request.form.get('age_max')
        job_start_date = datetime.strptime(job_start_date_str, '%Y-%m-%d').date() if job_start_date_str else None
        job_deadline = datetime.strptime(job_deadline_str, '%Y-%m-%d').date() if job_deadline_str else None

        job = Job(
            title=title,
            category=category,
            description=description,
            location=location,
            salary=salary,
            qualification=qualification,
            experience=experience,
            benefits=benefits,
            company_name=company_name,
            company_address=company_address,
            company_website=company_website,
            company_email=company_email,
            company_phone=company_phone,
            job_type='large',
            posted_by=current_user.id,
            company_logo=company_logo,
            status='Pending',
            job_start_date=job_start_date,
            job_deadline=job_deadline,
            age_requirement_min=int(age_min) if age_min else None,
            age_requirement_max=int(age_max) if age_max else None
        )
        db.session.add(job)
        db.session.commit()
        # 📧 Send email to employer
        send_job_submission_email(job, current_user)
        flash("Large job submitted for admin review.", "info")
        return redirect(url_for('index'))
    return render_template('post_job_large.html')

# -------------------- JOB DETAILS & APPLY --------------------
@app.route('/job/<int:job_id>')
def job_details(job_id):
    job = Job.query.get_or_404(job_id)
    poster = User.query.get(job.posted_by)

    # Only real admin user can be admin.
    is_admin = current_user.is_authenticated and getattr(current_user, "is_admin", False)

    return render_template(
        'job_details.html',
        job=job,
        poster=poster,
        is_admin=is_admin
    )
@app.route('/apply_job/<int:job_id>', methods=['GET', 'POST'])
@login_required
def apply_job(job_id):
    job = Job.query.get_or_404(job_id)

    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        age = request.form.get('age')
        experience = request.form.get('experience')
        cover_letter = request.form.get('cover_letter')

        # ---------------- DUPLICATE CHECK ----------------
        existing = Application.query.filter_by(
            job_id=job.id,
            user_id=current_user.id
        ).first()

        if existing:
            flash("You have already applied for this job.", "warning")
            return redirect(url_for('job_details', job_id=job.id))

        resume_file = request.files.get('resume')
        resume_filename = None

        if resume_file and resume_file.filename:
            if allowed_file(resume_file.filename):
                filename = secure_filename(
                    f"{int(datetime.utcnow().timestamp())}_{resume_file.filename}"
                )
                resume_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                resume_filename = filename
            else:
                flash("Resume must be PDF.", "danger")
                return redirect(url_for('job_details', job_id=job.id))

        # ---------------- SAVE APPLICATION ----------------
        new_app = Application(
            job_id=job.id,
            user_id=current_user.id,
            full_name=full_name,
            email=email,
            phone=phone,
            age=int(age) if age else None,
            experience=float(experience) if experience else None,
            cover_letter=cover_letter,
            resume=resume_filename,
            status='Pending'
        )

        db.session.add(new_app)
        db.session.commit()

        # ---------------- EMAIL EMPLOYER ----------------
        employer = User.query.get(job.posted_by)

        if employer and employer.email:
            try:
                msg = Message(
                    subject=f"[OurJobs] New application – {job.title}",
                    recipients=[employer.email]
                )
                msg.html = f"""
                <p>Hello {employer.name or 'Employer'},</p>

                <p>A new candidate has applied for your job.</p>

                <ul>
                  <li><strong>Job:</strong> {job.title}</li>
                  <li><strong>Applicant:</strong> {full_name}</li>
                  <li><strong>Applied on:</strong> {datetime.utcnow().strftime('%d %b %Y')}</li>
                </ul>

                <p>Please login to view full details.</p>
                <p><strong>OurJobs Team</strong></p>
                """
                mail.send(msg)
            except Exception as e:
                print("Email error:", e)

        flash("Application submitted successfully!", "success")
        return redirect(url_for('my_applications'))

    return render_template('apply_job.html', job=job)
@app.route('/my_applications')
@login_required
def my_applications():
    apps = Application.query.filter_by(user_id=current_user.id).order_by(Application.applied_at.desc()).all()
    return render_template('my_applications.html', applications=apps)

@app.route('/resumes/<filename>')
@login_required
def download_resume(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# -------------------- VIEW APPLICANTS --------------------
@app.route('/view_applicants/<int:job_id>')
@login_required
def view_applicants(job_id):
    job = Job.query.get_or_404(job_id)

    # poster or admin only
    if job.posted_by != current_user.id and not current_user.is_admin:
        flash("Not authorized", "danger")
        return redirect(url_for('index'))

    applicants = Application.query.filter_by(
        job_id=job.id
    ).order_by(Application.applied_at.desc()).all()

    # ✅ AUTO MARK AS VIEWED (only employer)
    if current_user.id == job.posted_by:
        for app in applicants:
            if app.status == 'Pending':
                app.status = 'Viewed'
        db.session.commit()

    return render_template(
        'view_applicants.html',
        job=job,
        applicants=applicants
    )




# -------------------- SUPPORT --------------------
@app.route('/support', methods=['GET', 'POST'])
@app.route('/customer_support', methods=['GET', 'POST'], endpoint='customer_support')
def customer_support():
    if request.method == 'POST':
        name = request.form.get('name') or (current_user.name if current_user.is_authenticated else 'Anonymous')
        email = request.form.get('email') or (current_user.email if current_user.is_authenticated else '')
        subject = request.form.get('subject')
        message = request.form.get('message')
        msg = SupportMessage(name=name, email=email, subject=subject, message=message)
        db.session.add(msg)
        db.session.commit()
        flash("Message sent. We'll contact you soon.", "success")
        return redirect(url_for('customer_support'))
    return render_template('support.html')

#-------------------- ADMIN --------------------
@app.route('/admin/login', methods=['GET', 'POST'])
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        # Check admin user (stored in User table)
        admin = User.query.filter_by(email=email, is_admin=True).first()

        if admin and admin.check_password(password):
            session['admin_id'] = admin.id
            session['admin_logged_in'] = True
            session['admin_flash'] = "Welcome admin."
            return redirect(url_for('admin_dashboard'))

        # fallback env admin (optional)
        env_email = os.getenv('ADMIN_EMAIL')
        env_pass = os.getenv('ADMIN_PASSWORD')
        if env_email and email == env_email and password == env_pass:
            session['admin_logged_in'] = True
            flash("Logged in as environment admin.", "success")
            return redirect(url_for('admin_dashboard'))

        flash("Invalid credentials.", "danger")

    return render_template('admin_login.html')

@app.route('/admin/create_subadmin', methods=['GET', 'POST'])
def create_subadmin():
    if not session.get('admin_logged_in'):
        flash("Admin login required.", "warning")
        return redirect(url_for('admin_login'))

    current_admin = User.query.get(session.get('admin_id'))

    if not current_admin.is_super_admin:
        flash("Only super admin can create sub-admins.", "danger")
        return redirect(url_for('admin_dashboard'))

    roles = AdminRole.query.all()

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email').lower()
        password = request.form.get('password')
        role_id = request.form.get('role_id')

        if User.query.filter_by(email=email).first():
            flash("Email already exists.", "danger")
            return redirect(url_for('create_subadmin'))

        subadmin = User(
            name=name,
            email=email,
            role='subadmin',
            is_admin=True,
            is_super_admin=False,
            admin_role_id=role_id
        )
        subadmin.set_password(password)

        db.session.add(subadmin)
        db.session.commit()

        flash("Sub-admin created successfully.", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_create_subadmin.html', roles=roles)
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_id', None)
    flash("Logged out admin.", "info")
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        flash("Admin login required.", "warning")
        return redirect(url_for('admin_login'))

    current_admin = User.query.get(session.get('admin_id'))

    if not current_admin:
        session.clear()
        flash("Session expired. Please login again.", "danger")
        return redirect(url_for('admin_login'))

    # ---------------- USERS (NON ADMINS ONLY) ----------------
    users = User.query.filter(User.is_admin == False).all()

    total_users = User.query.filter(User.is_admin == False).count()

    total_employers = User.query.filter(
        User.role == 'employer',
        User.is_admin == False
    ).count()

    total_jobseekers = User.query.filter(
        User.role == 'jobseeker',
        User.is_admin == False
    ).count()

    # ---------------- SUB ADMINS ----------------
    subadmins = User.query.filter(
        User.is_admin == True,
        User.is_super_admin == False,
        User.is_active == True
    ).all()

    # ---------------- JOBS ----------------
    pending_jobs = Job.query.filter_by(status='Pending').all()
    approved_jobs = Job.query.filter_by(status='Approved').all()
    rejected_jobs = Job.query.filter_by(status='Rejected').all()

    total_jobs = Job.query.count()
    pending_count = Job.query.filter_by(status='Pending').count()
    approved_count = Job.query.filter_by(status='Approved').count()

    # ---------------- SUPPORT ----------------
    messages = SupportMessage.query.all()
    support_pending = SupportMessage.query.filter_by(status='Pending').count()

    return render_template(
        'admin_dashboard.html',
        current_admin=current_admin,

        # tables
        users=users,
        subadmins=subadmins,

        # jobs
        pending_jobs=pending_jobs,
        approved_jobs=approved_jobs,
        rejected_jobs=rejected_jobs,

        # support
        messages=messages,

        # counts
        total_users=total_users,
        total_employers=total_employers,
        total_jobseekers=total_jobseekers,
        total_jobs=total_jobs,
        pending_count=pending_count,
        approved_count=approved_count,
        support_pending=support_pending
    )

@app.route('/admin/delete_subadmin/<int:user_id>')
def admin_delete_subadmin(user_id):
    # 1️⃣ Must be logged in as admin
    if not session.get('admin_logged_in'):
        flash("Admin login required.", "warning")
        return redirect(url_for('admin_login'))

    # 2️⃣ Current admin
    current_admin = User.query.get(session.get('admin_id'))

    # 3️⃣ Only super admin allowed
    if not current_admin or not current_admin.is_super_admin:
        flash("Only Super Admin can manage sub-admins.", "danger")
        return redirect(url_for('admin_dashboard'))

    # 4️⃣ Target user
    user = User.query.get_or_404(user_id)

    # 5️⃣ Safety checks
    if user.is_super_admin:
        flash("Cannot deactivate a Super Admin.", "danger")
        return redirect(url_for('admin_dashboard'))

    if not user.is_admin:
        flash("This user is not a sub-admin.", "warning")
        return redirect(url_for('admin_dashboard'))

    if user.id == current_admin.id:
        flash("You cannot deactivate yourself.", "danger")
        return redirect(url_for('admin_dashboard'))

    # 6️⃣ ✅ DEACTIVATE (NOT DELETE)
    user.is_active = False
    db.session.commit()

    # 7️⃣ Activity log (SAFE now)
    log = AdminActivityLog(
        admin_id=current_admin.id,
        action="Deactivated Sub-Admin",
        target_type="user",
        target_id=user.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()

    flash("Sub-admin deactivated successfully.", "success")
    return redirect(url_for('admin_dashboard'))
@app.route('/admin/job/<int:job_id>')
def admin_view_job(job_id):
    if not session.get('admin_logged_in'):
        flash("Admin login required.", "warning")
        return redirect(url_for('admin_login'))
    job = Job.query.get_or_404(job_id)
    poster = User.query.get(job.posted_by)
    return render_template('admin_view_job.html', job=job, poster=poster)



@app.route('/admin/reject_job/<int:job_id>')
@permission_required("manage_jobs")
def reject_job(job_id):
    if not session.get('admin_logged_in'):
        flash("Admin login required.", "warning")
        return redirect(url_for('admin_login'))

    job = Job.query.get_or_404(job_id)

    # ✅ FIX: get employer object
    employer = User.query.get(job.posted_by)

    job.status = 'Rejected'
    db.session.commit()

    # ❗ rejection reason (later you can make this dynamic)
    reason = "Incomplete job details or policy violation."

    # 📧 Send rejection email
    if employer:
        send_job_rejected_email(job, employer, reason)

        # 🔔 In-app notification
        notif = Notification(
            user_id=employer.id,
            message=f"❌ Your job '{job.title}' was rejected. Reason: {reason}"
        )
        db.session.add(notif)

    # 📝 Correct admin activity log
    log = AdminActivityLog(
        admin_id=session.get('admin_id'),
        action="Rejected Job",
        target_type="job",
        target_id=job.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)

    db.session.commit()

    flash("Job rejected.", "danger")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_job/<int:job_id>')
def admin_delete_job(job_id):
    if not session.get('admin_logged_in'):
        flash("Admin login required.", "warning")
        return redirect(url_for('admin_login'))
    job = Job.query.get_or_404(job_id)
    # delete all related applications
    Application.query.filter_by(job_id=job.id).delete()
    db.session.delete(job)
    db.session.commit()
    flash("Job deleted.", "info")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete_user/<int:user_id>')
@permission_required("manage_users")
def admin_delete_user(user_id):
    if not session.get('admin_logged_in'):
        flash("Admin login required.", "warning")
        return redirect(url_for('admin_login'))
    user = User.query.get_or_404(user_id)
    # delete employer profile
    if user.employer_profile:
        db.session.delete(user.employer_profile)
    # delete jobs & their applications
    for j in user.jobs:
        Application.query.filter_by(job_id=j.id).delete()
        db.session.delete(j)
    # delete user's applications
    Application.query.filter_by(user_id=user.id).delete()
    db.session.delete(user)
    db.session.commit()
    log = AdminActivityLog(
        admin_id=session.get('admin_id'),
        action="Approved Job",
        target_type="job",
        target_id=job.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    flash("User and related data deleted.", "info")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/support')
@admin_required
def admin_support():
    messages = SupportMessage.query.order_by(SupportMessage.created_at.desc()).all()
    return render_template('admin_support.html', messages=messages)

@app.route('/admin/support/resolve/<int:msg_id>')
@admin_required
@permission_required("view_logs")
def admin_support_resolve(msg_id):
    msg = SupportMessage.query.get_or_404(msg_id)
    msg.status = "Resolved"
    db.session.commit()
    log = AdminActivityLog(
        admin_id=session.get('admin_id'),
        action="Approved Job",
        target_type="job",
        target_id=job.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)
    db.session.commit()
    flash("Message resolved.", "success")
    return redirect(url_for('admin_support'))

@app.route('/admin/support/delete/<int:msg_id>')
@admin_required
def admin_support_delete(msg_id):
    msg = SupportMessage.query.get_or_404(msg_id)
    db.session.delete(msg)
    db.session.commit()
    flash("Message deleted.", "info")
    return redirect(url_for('admin_support'))

@app.route('/category/<slug>')
def category_jobs(slug):
    category_name = slug.replace('-', ' ').title()
    jobs = Job.query.filter(Job.category.ilike(f"%{category_name}%")).paginate(per_page=12)
    return render_template("category_jobs.html", category=category_name, jobs=jobs)

@app.route('/select_job_type')
def select_job_type():
    if not current_user.is_authenticated or current_user.role != 'employer':
        flash("Only employers can post jobs.", "warning")
        return redirect(url_for('login'))
    return render_template('select_job_type.html')
@app.route('/admin/approve_job/<int:job_id>')
@permission_required("manage_jobs")
def approve_job(job_id):
    if not session.get('admin_logged_in'):
        flash("Admin login required.", "warning")
        return redirect(url_for('admin_login'))

    job = Job.query.get_or_404(job_id)

    # ✅ FIX: get employer object
    employer = User.query.get(job.posted_by)

    job.status = 'Approved'
    db.session.commit()

    # 📧 Send approval email
    if employer:
        send_job_approved_email(job, employer)

        # 🔔 In-app notification
        notif = Notification(
            user_id=employer.id,
            message=f"🎉 Your job '{job.title}' has been approved!"
        )
        db.session.add(notif)

    # 📝 Admin activity log
    log = AdminActivityLog(
        admin_id=session.get('admin_id'),
        action="Approved Job",
        target_type="job",
        target_id=job.id,
        ip_address=request.remote_addr
    )
    db.session.add(log)

    db.session.commit()

    flash("Job approved.", "success")
    return redirect(url_for('admin_dashboard'))

@app.context_processor
def inject_notifications():
    if current_user.is_authenticated:
        notes = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()

        # Mark notifications as read immediately
        for n in notes:
            n.is_read = True
        db.session.commit()

        return dict(user_notifications=notes)

    return dict(user_notifications=[])

@app.after_request
def mark_notifications_read(response):
    if current_user.is_authenticated:
        unread = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
        for n in unread:
            n.is_read = True
        db.session.commit()
    return response

@app.route('/employer/view_applications/<int:job_id>')
@login_required
def employer_view_applications(job_id):
    job = Job.query.get_or_404(job_id)

    if job.posted_by != current_user.id:
        flash("Not authorized", "danger")
        return redirect(url_for('profile'))

    applications = Application.query.filter_by(job_id=job.id).all()

    for app in applications:
        if app.status == 'Pending':
            app.status = 'Viewed'

    db.session.commit()

    return render_template(
        'view_applicants.html',
        job=job,
        applications=applications
    )
@app.route('/select_application/<int:app_id>')
@login_required
def select_application(app_id):
    application = Application.query.get_or_404(app_id)
    job = Job.query.get_or_404(application.job_id)

    # Security: only job poster
    if job.posted_by != current_user.id:
        flash("Not authorized", "danger")
        return redirect(url_for('index'))

    application.status = 'Selected'
    db.session.commit()

    # 📧 EMAIL JOBSEEKER (SELECTED)
    try:
        msg = Message(
            subject=f"[OurJobs] You are selected – {job.title}",
            recipients=[application.email]
        )
        msg.html = f"""
        <p>Hello {application.full_name},</p>

        <p>Congratulations 🎉</p>

        <p>You have been <strong>SELECTED</strong> for the job:</p>

        <ul>
          <li><strong>Job Title:</strong> {job.title}</li>
          <li><strong>Company:</strong> {job.company_name or 'Employer'}</li>
        </ul>

        <p>The employer may contact you soon.</p>

        <p>Best wishes,<br>
        <strong>OurJobs Team</strong></p>
        """
        mail.send(msg)
    except Exception as e:
        print("Selection email error:", e)

    flash("Applicant selected and notified by email.", "success")
    return redirect(url_for('view_applicants', job_id=job.id))

@app.route('/reject_application/<int:app_id>')
@login_required
def reject_application(app_id):
    application = Application.query.get_or_404(app_id)
    job = Job.query.get_or_404(application.job_id)

    # Security: only job poster
    if job.posted_by != current_user.id:
        flash("Not authorized", "danger")
        return redirect(url_for('index'))

    application.status = 'Rejected'
    db.session.commit()

    # 📧 EMAIL JOBSEEKER (REJECTED)
    try:
        msg = Message(
            subject=f"[OurJobs] Application update – {job.title}",
            recipients=[application.email]
        )
        msg.html = f"""
        <p>Hello {application.full_name},</p>

        <p>Thank you for applying for the position:</p>

        <p><strong>{job.title}</strong></p>

        <p>After careful consideration, the employer has decided to move forward with other candidates.</p>

        <p>We encourage you to apply for other opportunities on OurJobs.</p>

        <p>Best regards,<br>
        <strong>OurJobs Team</strong></p>
        """
        mail.send(msg)
    except Exception as e:
        print("Rejection email error:", e)

    flash("Applicant rejected and notified by email.", "info")
    return redirect(url_for('view_applicants', job_id=job.id))





@app.route('/admin/activity')
def admin_activity():
    if not session.get('admin_logged_in'):
        flash("Admin login required.", "warning")
        return redirect(url_for('admin_login'))

    logs = AdminActivityLog.query.order_by(
        AdminActivityLog.created_at.desc()
    ).limit(200).all()

    return render_template(
        'admin_activity.html',
        logs=logs
    )


def permission_required(permission_code):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not session.get('admin_logged_in'):
                flash("Admin login required.", "warning")
                return redirect(url_for('admin_login'))

            admin = User.query.get(session.get('admin_id'))
            if not admin or not admin.has_permission(permission_code):
                flash("You do not have permission for this action.", "danger")
                return redirect(url_for('admin_dashboard'))

            return f(*args, **kwargs)
        return wrapper
    return decorator

def admin_has_permission(required_role):
    if not session.get('admin_logged_in'):
        return False

    admin = User.query.get(session.get('admin_id'))
    if not admin or not admin.is_admin:
        return False

    if admin.admin_role == 'super_admin':
        return True

    return admin.admin_role == required_role

@app.route('/_setup_admin_roles')
def setup_admin_roles():
    # ---- PERMISSIONS ----
    permissions = {
        "approve_jobs": "Approve job postings",
        "reject_jobs": "Reject job postings",
        "view_jobs": "View job details",
        "manage_users": "Manage users",
        "delete_users": "Delete users",
        "resolve_support": "Resolve support tickets",
        "view_logs": "View admin activity logs"
    }

    perm_objects = {}
    for code, desc in permissions.items():
        perm = Permission.query.filter_by(code=code).first()
        if not perm:
            perm = Permission(code=code, description=desc)
            db.session.add(perm)
        perm_objects[code] = perm

    db.session.commit()

    # ---- ROLES ----
    roles = {
        "Job Admin": ["approve_jobs", "reject_jobs", "view_jobs"],
        "User Admin": ["manage_users", "delete_users", "view_logs"],
        "Support Admin": ["resolve_support", "view_logs"]
    }

    for role_name, perms in roles.items():
        role = AdminRole.query.filter_by(name=role_name).first()
        if not role:
            role = AdminRole(name=role_name)
            db.session.add(role)
            db.session.commit()

        role.permissions = [perm_objects[p] for p in perms]

    db.session.commit()

    return "✅ Admin roles & permissions created successfully"


# -------------------- OTHER --------------------
@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(e):
    flash("File too large. Max 5MB.", "danger")
    return redirect(request.referrer or url_for('index'))

# -------------------- SETUP & RUN --------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        ensure_admin_exists()
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))