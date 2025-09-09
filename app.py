from datetime import datetime, date, timedelta
from functools import wraps
import io
import os
import logging
import secrets
from typing import Optional, List, Dict, Any

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import pandas as pd
from sqlalchemy import func, and_, or_
from sqlalchemy.exc import IntegrityError

# Initialize Flask app with enhanced configuration
app = Flask(__name__)

# Configuration Management
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///egas.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    WTF_CSRF_ENABLED = True
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file upload

app.config.from_object(Config)
db = SQLAlchemy(app)

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s'
)
logger = logging.getLogger(__name__)


# ============= UTILITY FUNCTIONS =============
def validate_email(email: str) -> bool:
    """Basic email validation - relaxed for demo emails."""
    import re
    # Allow both standard emails and demo emails ending with @egas
    standard_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    demo_pattern = r'^[a-zA-Z0-9._%+-]+@egas$'
    
    return (re.match(standard_pattern, email) is not None or 
            re.match(demo_pattern, email) is not None)


def sanitize_input(text: str, max_length: int = 500) -> str:
    """Sanitize user input by stripping whitespace and limiting length."""
    if not text:
        return ''
    return text.strip()[:max_length]


def validate_date_string(date_str: str) -> Optional[date]:
    """Validate and parse date string in YYYY-MM-DD format."""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return None


def get_user_by_id(user_id: int) -> Optional['User']:
    """Get user by ID with error handling."""
    try:
        return User.query.get(user_id)
    except Exception as e:
        logger.error(f"Error fetching user {user_id}: {e}")
        return None


def safe_int_conversion(value: str, default: int = 0) -> int:
    """Safely convert string to integer."""
    try:
        return int(value) if value else default
    except (ValueError, TypeError):
        return default


def paginate_query(query, page: int = 1, per_page: int = 50):
    """Add pagination to SQLAlchemy query."""
    return query.paginate(
        page=max(1, page), 
        per_page=min(per_page, 100), 
        error_out=False
    )


def log_user_action(user_id: int, action: str, details: str = ''):
    """Log user actions for audit trail."""
    logger.info(f"User {user_id} performed action: {action} - {details}")


def calculate_task_metrics(tasks: List['Task']) -> Dict[str, Any]:
    """Calculate comprehensive task metrics."""
    if not tasks:
        return {
            'total': 0, 'completed': 0, 'overdue': 0, 'on_time': 0,
            'completion_rate': 0, 'on_time_rate': 0, 'overdue_rate': 0
        }
    
    today = date.today()
    total = len(tasks)
    completed = sum(1 for t in tasks if t.status == 'Completed')
    overdue = sum(1 for t in tasks if t.due_date and t.due_date < today and t.status != 'Completed')
    on_time = sum(1 for t in tasks 
                  if t.status == 'Completed' and t.due_date and t.completed_at 
                  and t.completed_at.date() <= t.due_date)
    
    return {
        'total': total,
        'completed': completed,
        'overdue': overdue,
        'on_time': on_time,
        'completion_rate': round((completed/total)*100) if total else 0,
        'on_time_rate': round((on_time/total)*100) if total else 0,
        'overdue_rate': round((overdue/total)*100) if total else 0
    }


def _compute_emp_perf(user):
    # Compute 8 weekly buckets of completion% per employee using due_date.
    # Employees: only their own series. Managers with department: employees in that dept.
    # Managers without department: top 6 employees by volume.
    from collections import defaultdict
    today = date.today()
    start = today - timedelta(weeks=7)
    labels = [(start + timedelta(weeks=i)).strftime('%b %d') for i in range(8)]

    # Select employees
    if user.role == 'employee':
        emps = [user]
    else:
        q = User.query.filter(User.role == 'employee')
        if user.department_id:
            q = q.filter(User.department_id == user.department_id)
        emps = q.all()

    # Relevant tasks
    all_tasks = Task.query.filter(
        Task.due_date.isnot(None),
        Task.due_date >= start,
        Task.is_private == False
    ).all()

    totals = {e.id: [0]*8 for e in emps}
    comps  = {e.id: [0]*8 for e in emps}
    for t in all_tasks:
        if t.assignee_id in totals:
            idx = (t.due_date - start).days // 7
            if 0 <= idx < 8:
                totals[t.assignee_id][idx] += 1
                if t.status == 'Completed':
                    comps[t.assignee_id][idx] += 1

    # Limit to top 6 if manager without department
    if user.role == 'manager' and not user.department_id:
        emps = sorted(emps, key=lambda e: (sum(totals[e.id]), e.id), reverse=True)[:6]

    series = []
    for e in emps:
        vals = []
        for i in range(8):
            tot = totals[e.id][i]
            comp = comps[e.id][i]
            vals.append(round(100*comp/tot, 1) if tot else 0.0)
        series.append({'name': e.name, 'values': vals})
    return labels, series





def _run_migration():
    """Run database migrations safely."""
    try:
        # Simple migration - just add missing columns if they don't exist
        try:
            db.session.execute(db.text("ALTER TABLE task ADD COLUMN is_private BOOLEAN NOT NULL DEFAULT 0"))
            logger.info("Added is_private column to task table")
        except Exception:
            pass  # Column probably exists
            
        try:
            db.session.execute(db.text("ALTER TABLE task ADD COLUMN estimated_hours FLOAT"))
            db.session.execute(db.text("ALTER TABLE task ADD COLUMN actual_hours FLOAT"))
            db.session.execute(db.text("ALTER TABLE task ADD COLUMN tags VARCHAR(500)"))
            logger.info("Added extended columns to task table")
        except Exception:
            pass
            
        db.session.commit()
        logger.info("Database migration completed successfully")
        
    except Exception as e:
        logger.error(f"Migration error: {e}")
        db.session.rollback()


# ---------------- Models ----------------
class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False, default='employee')  # manager | employee
    password_hash = db.Column(db.String(255), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'))
    department = db.relationship('Department', backref=db.backref('users', lazy=True))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

    def set_password(self, password: str):
        """Hash and set the user password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password: str) -> bool:
        """Check if provided password matches the hash."""
        # Handle both old plain text passwords and new hashed passwords
        if self.password_hash:
            return check_password_hash(self.password_hash, password)
        # Fallback for legacy plain text passwords (if password_hash is None)
        # This should only happen during migration
        try:
            # Check if we have old 'password' field
            if hasattr(self, '_password_plain'):
                return self._password_plain == password
        except:
            pass
        return False
    
    def is_locked(self) -> bool:
        """Check if account is currently locked due to failed login attempts."""
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False
    
    def increment_failed_login(self):
        """Increment failed login attempts and lock account if necessary."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=30)
        db.session.commit()
    
    def reset_failed_login(self):
        """Reset failed login attempts on successful login."""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.utcnow()
        db.session.commit()
    
    def can_access_task(self, task: 'Task') -> bool:
        """Check if user can access a specific task."""
        if self.role == 'manager':
            return True
        if task.assignee_id == self.id:
            return True
        if task.is_private:
            return task.creator_id == self.id
        return task.department_id == self.department_id
    
    def __repr__(self):
        return f'<User {self.email}>'
    
    # Backward compatibility property
    @property
    def password(self):
        raise AttributeError('Password is not readable')
    
    @password.setter
    def password(self, password):
        self.set_password(password)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, index=True)
    description = db.Column(db.Text, nullable=True)
    priority = db.Column(db.String(20), default='Medium', index=True)  # Critical/High/Medium/Low
    status = db.Column(db.String(30), default='New', index=True)       # New/In Progress/Blocked/Completed
    progress_pct = db.Column(db.Integer, default=0)
    due_date = db.Column(db.Date, nullable=True, index=True)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    assignee = db.relationship('User', foreign_keys=[assignee_id])
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), index=True)
    creator = db.relationship('User', foreign_keys=[creator_id])
    department_id = db.Column(db.Integer, db.ForeignKey('department.id'), nullable=True, index=True)
    department = db.relationship('Department', backref=db.backref('tasks', lazy=True))
    is_private = db.Column(db.Boolean, nullable=False, default=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    estimated_hours = db.Column(db.Float, nullable=True)
    actual_hours = db.Column(db.Float, nullable=True)
    tags = db.Column(db.String(500), nullable=True)  # Comma-separated tags

    def is_overdue(self) -> bool:
        """Check if task is overdue."""
        return (self.due_date and 
                self.due_date < date.today() and 
                self.status != 'Completed')
    
    def days_until_due(self) -> Optional[int]:
        """Calculate days until due date."""
        if not self.due_date:
            return None
        delta = self.due_date - date.today()
        return delta.days
    
    def is_completed_on_time(self) -> bool:
        """Check if task was completed on time."""
        return (self.status == 'Completed' and 
                self.due_date and 
                self.completed_at and 
                self.completed_at.date() <= self.due_date)
    
    def get_priority_weight(self) -> int:
        """Get numeric weight for priority sorting."""
        priority_weights = {
            'Critical': 4,
            'High': 3,
            'Medium': 2,
            'Low': 1
        }
        return priority_weights.get(self.priority, 2)
    
    def update_progress(self, progress: int, status: str = None):
        """Update task progress with validation."""
        self.progress_pct = max(0, min(100, progress))
        if status:
            self.status = status
        if self.progress_pct == 100 and not self.completed_at:
            self.completed_at = datetime.utcnow()
            self.status = 'Completed'
        self.updated_at = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert task to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'priority': self.priority,
            'status': self.status,
            'progress_pct': self.progress_pct,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'assignee': self.assignee.name if self.assignee else None,
            'department': self.department.name if self.department else None,
            'is_private': self.is_private,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_overdue': self.is_overdue(),
            'days_until_due': self.days_until_due()
        }
    
    def __repr__(self):
        return f'<Task {self.id}: {self.title[:30]}...>'

    # Add database constraints and indexes
    __table_args__ = (
        db.Index('idx_task_assignee_status', 'assignee_id', 'status'),
        db.Index('idx_task_dept_private', 'department_id', 'is_private'),
        db.Index('idx_task_due_status', 'due_date', 'status'),
    )

# ============= ENHANCED AUTH HELPERS =============
def get_current_user() -> Optional[User]:
    """Get the currently logged-in user."""
    user_id = session.get('user_id')
    if user_id:
        return get_user_by_id(user_id)
    return None


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        if not user.is_active:
            flash('Your account has been deactivated.', 'error')
            session.clear()
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapper


def manager_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        if user.role != 'manager':
            log_user_action(user.id, 'UNAUTHORIZED_ACCESS_ATTEMPT', f'Tried to access manager-only resource: {request.endpoint}')
            return abort(403)
        return fn(*args, **kwargs)
    return wrapper


def validate_session():
    """Validate and refresh session if needed."""
    if 'user_id' in session:
        user = get_current_user()
        if not user or not user.is_active:
            session.clear()
            return False
        
        # Update session timestamp
        session.permanent = True
        session['last_activity'] = datetime.utcnow().isoformat()
        return True
    return False


@app.before_request
def before_request():
    """Run before each request to validate session and log activity."""
    # Skip validation for static files and auth endpoints
    if request.endpoint in ['static', 'login', 'seed']:
        return
    
    # Validate session for protected routes
    if request.endpoint and not request.endpoint.startswith('auth.'):
        validate_session()

# ------------- Views --------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Redirect if already logged in
    if get_current_user():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            email = sanitize_input(request.form.get('email', '')).lower()
            password = request.form.get('password', '')
            
            # Input validation
            if not email or not password:
                flash('Email and password are required.', 'error')
                return render_template('login.html')
            
            if not validate_email(email):
                flash('Please enter a valid email address.', 'error')
                return render_template('login.html')
            
            # Find user and check password
            user = User.query.filter_by(email=email).first()
            
            if not user:
                # Prevent user enumeration - same message for non-existent users
                log_user_action(0, 'LOGIN_ATTEMPT_INVALID_USER', email)
                flash('Invalid email or password.', 'error')
                return render_template('login.html')
            
            # Check if account is locked
            if user.is_locked():
                log_user_action(user.id, 'LOGIN_ATTEMPT_LOCKED_ACCOUNT', email)
                flash('Account is temporarily locked due to too many failed login attempts. Please try again later.', 'error')
                return render_template('login.html')
            
            # Check if account is active
            if not user.is_active:
                log_user_action(user.id, 'LOGIN_ATTEMPT_INACTIVE_ACCOUNT', email)
                flash('Your account has been deactivated. Please contact an administrator.', 'error')
                return render_template('login.html')
            
            # Verify password
            if not user.check_password(password):
                user.increment_failed_login()
                log_user_action(user.id, 'LOGIN_ATTEMPT_WRONG_PASSWORD', email)
                flash('Invalid email or password.', 'error')
                return render_template('login.html')
            
            # Successful login
            user.reset_failed_login()
            session.permanent = True
            session['user_id'] = user.id
            session['role'] = user.role
            session['login_time'] = datetime.utcnow().isoformat()
            
            log_user_action(user.id, 'LOGIN_SUCCESS', email)
            flash(f'Welcome back, {user.name}!', 'success')
            
            # Redirect to next page or dashboard
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An error occurred during login. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    user = get_current_user()
    if user:
        log_user_action(user.id, 'LOGOUT', '')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    try:
        user = get_current_user()
        if not user:
            return redirect(url_for('login'))
            
        # Optimize: Load departments with a single query
        departments = Department.query.order_by(Department.name.asc()).all()

        # Build optimized query for user's scoped tasks
        scoped_query = Task.query
        if user.role == 'manager':
            scoped_query = scoped_query.filter(
                or_(Task.is_private == False, Task.assignee_id == user.id)
            )
        else:
            if user.department_id:
                scoped_query = scoped_query.filter(
                    or_(
                        and_(Task.department_id == user.department_id, Task.is_private == False),
                        Task.assignee_id == user.id
                    )
                )
            else:
                scoped_query = scoped_query.filter(Task.assignee_id == user.id)

        # Execute query and calculate metrics
        scoped_tasks = scoped_query.all()
        metrics = calculate_task_metrics(scoped_tasks)

        # Calculate department-specific metrics efficiently
        dept_metrics = []
        if user.role == 'manager':
            # Managers see all departments
            for dept in departments:
                dept_tasks = [t for t in scoped_tasks if t.department_id == dept.id]
                dept_metrics.append({
                    **calculate_task_metrics(dept_tasks),
                    'id': dept.id,
                    'name': dept.name
                })
        else:
            # Employees see only their department
            if user.department_id:
                user_dept = next((d for d in departments if d.id == user.department_id), None)
                if user_dept:
                    dept_tasks = [t for t in scoped_tasks if t.department_id == user.department_id]
                    dept_metrics.append({
                        **calculate_task_metrics(dept_tasks),
                        'id': user_dept.id,
                        'name': user_dept.name
                    })

        # Generate performance charts data
        emp_perf_labels, emp_perf_series = _compute_emp_perf(user)
        
        # Recent activity for dashboard
        recent_tasks = scoped_query.filter(
            Task.updated_at >= datetime.utcnow() - timedelta(days=7)
        ).order_by(Task.updated_at.desc()).limit(10).all()
        
        log_user_action(user.id, 'DASHBOARD_VIEW', '')
        
        return render_template('dashboard.html',
                             user=user, 
                             departments=departments,
                             metrics=metrics,
                             dept_metrics=dept_metrics, 
                             emp_perf_labels=emp_perf_labels, 
                             emp_perf_series=emp_perf_series,
                             recent_tasks=recent_tasks)
                             
    except Exception as e:
        logger.error(f"Dashboard error for user {session.get('user_id', 'unknown')}: {e}")
        flash('An error occurred loading the dashboard.', 'error')
        return render_template('dashboard.html', 
                             user=get_current_user(), 
                             departments=[], 
                             metrics={}, 
                             dept_metrics=[], 
                             emp_perf_labels=[], 
                             emp_perf_series=[], 
                             recent_tasks=[])


@app.route('/my', methods=['GET'])
@login_required
def my():
    """For managers: create form + manager personal tasks. For employees: their personal tasks."""
    u = User.query.get(session['user_id'])
    if u.role == 'manager':
        deps = Department.query.order_by(Department.name.asc()).all()

        # Build users_by_dept with idle flag (no active tasks)
        users_by_dept = {}
        for d in deps:
            members = User.query.filter(User.department_id == d.id, User.role == 'employee').all()
            users_by_dept[d.id] = []
            for m in members:
                active_count = Task.query.filter(Task.assignee_id == m.id, Task.status != 'Completed').count()
                users_by_dept[d.id].append({
                    "id": m.id,
                    "name": m.name,
                    "idle": active_count == 0
                })

        # Manager personal tasks (assignee == manager)
        my_tasks = Task.query.filter(Task.assignee_id == u.id).order_by(Task.due_date.is_(None), Task.due_date.asc()).all()
        return render_template('my_manager.html', user=u, deps=deps, users_by_dept=users_by_dept, my_tasks=my_tasks)

    else:
        my_tasks = Task.query.filter(Task.assignee_id == u.id) \
            .order_by(Task.due_date.is_(None), Task.due_date.asc()).all()
        return render_template('my_employee.html', user=u, my_tasks=my_tasks)

@app.route('/category/<int:dept_id>')
@login_required
def category_view(dept_id):
    u = User.query.get(session['user_id'])
    dept = Department.query.get_or_404(dept_id)
    if u.role != 'manager' and u.department_id != dept_id:
        return abort(403)
    tasks = Task.query.filter(Task.department_id == dept_id) \
        .order_by(Task.due_date.is_(None), Task.due_date.asc()).all()
    deps = Department.query.order_by(Department.name.asc()).all()
    return render_template('category.html', user=u, dept=dept, tasks=tasks, deps=deps)

# ------------- Task actions -------------
@app.route('/tasks/create', methods=['POST'])
@login_required
@manager_required
def create_task():
    title = request.form.get('title','').strip()
    description = request.form.get('description','').strip()
    priority = request.form.get('priority','Medium')
    due_date = request.form.get('due_date')
    dept_id = request.form.get('department_id')
    assignee_id = request.form.get('assignee_id')

    if not title:
        flash('Title is required', 'error')
        return redirect(url_for('my'))
    if not dept_id or not assignee_id:
        flash('Department and Assignee are required', 'error')
        return redirect(url_for('my'))

    # Validate assignee belongs to the selected department
    assignee = User.query.get(int(assignee_id))
    if not assignee or str(assignee.department_id) != str(dept_id):
        flash('Assignee must belong to the selected department', 'error')
        return redirect(url_for('my'))

    dept_id_val = int(dept_id)

    t = Task(
        title=title,
        description=description,
        priority=priority,
        due_date=datetime.strptime(due_date,'%Y-%m-%d').date() if due_date else None,
        assignee_id=int(assignee_id),
        creator_id=session['user_id'],
        department_id=dept_id_val,
        is_private=False,
        status='New',
        progress_pct=0
    )
    db.session.add(t)
    db.session.commit()
    flash('Task created', 'ok')
    return redirect(url_for('category_view', dept_id=dept_id_val))



@app.route('/tasks/<int:task_id>/receive', methods=['POST'])
@login_required
def receive_task(task_id):
    u = User.query.get(session['user_id'])
    t = Task.query.get_or_404(task_id)
    # Only assignee (or manager) can mark as received
    if t.assignee_id != u.id and u.role != 'manager':
        return abort(403)
    # Only if not already completed
    if t.status != 'Completed':
        t.status = 'Received'
        if t.progress_pct is None:
            t.progress_pct = 0
        db.session.commit()
        flash('Task marked as received', 'ok')
    return redirect(url_for('my'))
@app.route('/tasks/<int:task_id>/complete', methods=['POST'])
@login_required
def complete_task(task_id):
    u = User.query.get(session['user_id'])
    t = Task.query.get_or_404(task_id)
    if u.role != 'manager' and t.assignee_id != u.id:
        return abort(403)
    t.status = 'Completed'
    t.progress_pct = 100
    t.completed_at = datetime.utcnow()
    db.session.commit()
    flash('Task marked as completed', 'ok')
    # Redirect logic: if task is private or has no department, always go back to 'my'
    if t.is_private or t.department_id is None:
        return redirect(url_for('my'))
    # Managers can go back to their "My" view; employees return to the department category
    if u.role == 'manager':
        return redirect(url_for('my'))
    return redirect(url_for('category_view', dept_id=t.department_id))

@app.route('/tasks/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    u = User.query.get(session['user_id'])
    t = Task.query.get_or_404(task_id)
    if t.is_private:
        if u.id not in (t.assignee_id, t.creator_id) and u.role != 'manager':
            return abort(403)
    else:
        if u.role != 'manager':
            return abort(403)
    dept_id = t.department_id
    db.session.delete(t)
    db.session.commit()
    flash('Task deleted', 'warn')
    if t.is_private or not dept_id:
        return redirect(url_for('my'))
    return redirect(url_for('category_view', dept_id=dept_id))

@app.route('/tasks/self/create', methods=['POST'])
@login_required
def create_self_task():
    u = User.query.get(session['user_id'])
    title = request.form.get('title','').strip()
    description = request.form.get('description','').strip()
    priority = request.form.get('priority','Medium')
    due_date = request.form.get('due_date')

    if not title:
        flash('Title is required', 'error')
        return redirect(url_for('my'))

    t = Task(
        title=title,
        description=description,
        priority=priority,
        due_date=datetime.strptime(due_date,'%Y-%m-%d').date() if due_date else None,
        assignee_id=u.id,
        creator_id=u.id,
        department_id=None,
        is_private=True,
        status='New',
        progress_pct=0
    )
    db.session.add(t)
    db.session.commit()
    flash('Added to your To-Do list', 'ok')
    return redirect(url_for('my'))
# ------------- Report -------------------
@app.route('/weekly')
@login_required
@manager_required
def weekly():
    today = date.today()
    week_ago = today - timedelta(days=7)
    tasks = Task.query.filter(Task.created_at >= datetime.combine(week_ago, datetime.min.time())).all()

    records = [{
        'Task ID': t.id,
        'Title': t.title,
        'Department': t.department.name if t.department else '',
        'Assignee': t.assignee.name if t.assignee else '',
        'Priority': t.priority,
        'Status': t.status,
        'Progress %': t.progress_pct,
        'Due Date': t.due_date.isoformat() if t.due_date else '',
        'Created At': t.created_at.date().isoformat() if t.created_at else '',
        'Completed At': t.completed_at.date().isoformat() if t.completed_at else ''
    } for t in tasks]

    df = pd.DataFrame(records)
    total = len(records)
    completed = sum(1 for r in records if r['Status']=='Completed')
    overdue = sum(1 for r in tasks if r.due_date and r.due_date < today and r.status != 'Completed')

    if not df.empty:
        dept_summary = df.groupby('Department').agg({'Task ID':'count','Progress %':'mean'}).rename(
            columns={'Task ID':'Tasks','Progress %':'Avg Progress %'}).reset_index().to_dict(orient='records')
    else:
        dept_summary = []

    if request.args.get('format') == 'csv':
        csv_buf = io.StringIO()
        df.to_csv(csv_buf, index=False)
        return send_file(io.BytesIO(csv_buf.getvalue().encode('utf-8-sig')),
                         mimetype='text/csv', as_attachment=True,
                         download_name=f'egas_weekly_{today}.csv')

    return render_template('weekly.html',
                           today=today, week_ago=week_ago,
                           total=total, completed=completed, overdue=overdue,
                           dept_rows=dept_summary, rows=records)

# --------- Users Admin (manager-only) ----------
@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def admin_users():
    u = User.query.get(session['user_id'])
    if u.role != 'manager':
        return abort(403)

    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        password = (request.form.get('password') or '').strip()
        role = request.form.get('role') or 'employee'
        department_id = request.form.get('department_id')

        if not name or not email or not password:
            flash('Name, email, and password are required.', 'error')
            return redirect(url_for('admin_users'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'error')
            return redirect(url_for('admin_users'))

        if role == 'employee':
            if not department_id:
                flash('Department is required for employees.', 'error')
                return redirect(url_for('admin_users'))
            if not Department.query.get(int(department_id)):
                flash('Invalid department.', 'error')
                return redirect(url_for('admin_users'))
        else:
            department_id = None

        u_new = User(
            name=name,
            email=email,
            role=role,
            department_id=int(department_id) if department_id else None
        )
        u_new.set_password(password)
        db.session.add(u_new)
        db.session.commit()
        flash('User created successfully.', 'ok')
        return redirect(url_for('admin_users'))

    departments = Department.query.order_by(Department.name.asc()).all()
    users = User.query.order_by(User.role.desc(), User.name.asc()).all()
    return render_template('admin_users.html', users=users, departments=departments)

@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@login_required
def admin_user_delete(user_id):
    u = User.query.get(session['user_id'])
    if u.role != 'manager':
        return abort(403)
    target = User.query.get_or_404(user_id)
    if target.id == u.id:
        flash("You can't delete your own account while logged in.", 'error')
        return redirect(url_for('admin_users'))
    db.session.delete(target)
    db.session.commit()
    flash('User deleted.', 'warn')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/<int:user_id>/edit', methods=['POST'])
@login_required
def admin_user_edit(user_id):
    u = User.query.get(session['user_id'])
    if u.role != 'manager':
        return abort(403)
    target = User.query.get_or_404(user_id)
    name = (request.form.get('name') or '').strip()
    password = (request.form.get('password') or '').strip()
    role = request.form.get('role') or target.role
    department_id = request.form.get('department_id')

    if not name:
        flash('Name is required.', 'error')
        return redirect(url_for('admin_users'))

    target.name = name
    if password:
        target.set_password(password)
    target.role = role

    if role == 'employee':
        if not department_id:
            flash('Department is required for employees.', 'error')
            return redirect(url_for('admin_users'))
        dept_obj = Department.query.get(int(department_id))
        if not dept_obj:
            flash('Invalid department.', 'error')
            return redirect(url_for('admin_users'))
        target.department_id = dept_obj.id
    else:
        target.department_id = None

    db.session.commit()
    flash('User updated.', 'ok')
    return redirect(url_for('admin_users'))

# ------------- Seed ---------------------
@app.route('/debug-users')
def debug_users():
    """Debug route to check what users exist in database."""
    users = User.query.all()
    result = "<h1>Users in Database:</h1><ul>"
    for u in users:
        result += f"<li>Email: {u.email}, Name: {u.name}, Role: {u.role}, Has password_hash: {bool(u.password_hash)}</li>"
    result += "</ul>"
    return result

@app.route('/quick-login/<email>')
def quick_login_test(email):
    """Quick login for testing - bypasses form."""
    user = User.query.filter_by(email=email).first()
    if user and user.check_password('123'):
        session['user_id'] = user.id
        session['role'] = user.role
        session.permanent = True
        flash(f'Logged in as {user.name}', 'success')
        return redirect(url_for('dashboard'))
    else:
        return f"Login failed for {email}. User exists: {bool(user)}. Password OK: {user.check_password('123') if user else 'No user'}"

@app.route('/seed')
def seed():
    """Initialize database with sample data (admin, dept heads, many users, and many tasks)."""
    try:
        import random
        random.seed(42)

        db.create_all()
        _run_migration()

        # Departments
        dept_names = [
            'Operations Team','Cyber Security','Engineering',
            'Maintenance','IT & Digital','Finance','HR & Admin'
        ]
        for name in dept_names:
            if not Department.query.filter_by(name=name).first():
                db.session.add(Department(name=name))
        db.session.commit()

        departments = Department.query.all()

        # Global admin
        if not User.query.filter_by(email='admin@egas').first():
            admin = User(name='Global Admin', email='admin@egas', role='manager', department=None)
            admin.set_password('123')
            db.session.add(admin)
            db.session.commit()
        admin = User.query.filter_by(email='admin@egas').first()

        # Department heads (manager with department assigned)
        for d in departments:
            head_email = f"head_{d.name.split()[0].lower()}@egas"
            if not User.query.filter_by(email=head_email).first():
                head = User(name=f"Head of {d.name}", email=head_email, role='manager', department=d)
                head.set_password('123')
                db.session.add(head)
        db.session.commit()

        # Many employees per department
        for d in departments:
            existing = User.query.filter_by(role='employee', department=d).count()
            to_create = max(0, 50 - existing)  # ensure ~50 employees per department
            for i in range(to_create):
                email = f"{d.name.split()[0].lower()}{i+1}@egas"
                if not User.query.filter_by(email=email).first():
                    u = User(name=f"{d.name} Emp {i+1}", email=email, role='employee', department=d)
                    u.set_password('123')
                    db.session.add(u)
        db.session.commit()

        # Create lots of tasks
        all_users = User.query.filter_by(role='employee').all()
        priorities = ['Low','Medium','High','Critical']
        statuses = ['New','In Progress','Blocked','Completed']
        titles = [
            'Inspect station pumps', 'Audit access logs', 'Patch server firmware', 'Clean filters',
            'Calibrate sensors', 'Prepare monthly report', 'Upgrade WIFI APs', 'Train new hires',
            'Backup database', 'Replace worn belts', 'Monitor network traffic', 'Firewall rules review',
            'Safety drills', 'Vendor coordination', 'Ticket triage', 'Code review session'
        ]
        total_tasks = 1200
        created = 0
        for n in range(total_tasks):
            assignee = random.choice(all_users)
            dept_id = assignee.department_id
            pr = random.choices(priorities, weights=[2,5,3,1])[0]
            st = random.choices(statuses, weights=[4,5,1,3])[0]
            due = date.today() + timedelta(days=random.randint(-30, 45))
            title = random.choice(titles)
            desc = f"{title} - detailed step {random.randint(1,5)} for {assignee.name}"
            t = Task(
                title=title,
                description=desc,
                priority=pr,
                status=st,
                progress_pct=100 if st=='Completed' else random.randint(0, 95),
                due_date=due,
                assignee_id=assignee.id,
                creator_id=admin.id if admin else None,
                department_id=dept_id,
                is_private=False
            )
            if st=='Completed':
                t.completed_at = datetime.utcnow() - timedelta(days=random.randint(0,30))
            db.session.add(t)
            created += 1
            if created % 200 == 0:
                db.session.commit()
        db.session.commit()

        flash('Database seeded with admin, department heads, employees, and 1200 tasks.', 'success')
        logger.info("Database seeded with large fake dataset")
        return redirect(url_for('login'))
        
    except Exception as e:
        logger.error(f"Seeding error: {e}")
        flash('An error occurred during database seeding.', 'error')
        return redirect(url_for('login'))

# ============= API ENDPOINTS =============
@app.route('/api/tasks/<int:task_id>/progress', methods=['POST'])
@login_required
def update_task_progress(task_id):
    """API endpoint to update task progress."""
    try:
        user = get_current_user()
        task = Task.query.get_or_404(task_id)
        
        # Check permissions
        if not user.can_access_task(task):
            return jsonify({'error': 'Access denied'}), 403
            
        data = request.get_json()
        progress = safe_int_conversion(data.get('progress', 0))
        status = sanitize_input(data.get('status', ''))
        
        task.update_progress(progress, status)
        db.session.commit()
        
        log_user_action(user.id, 'TASK_PROGRESS_UPDATE', f'Task {task_id}: {progress}%')
        
        return jsonify({
            'success': True,
            'task': task.to_dict()
        })
        
    except Exception as e:
        logger.error(f"Progress update error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/dashboard/metrics')
@login_required
def dashboard_metrics():
    """API endpoint for dashboard metrics."""
    try:
        user = get_current_user()
        # Use same logic as dashboard but return JSON
        # This would be useful for real-time updates
        metrics = {'placeholder': 'for future real-time updates'}
        return jsonify(metrics)
    except Exception as e:
        logger.error(f"Metrics API error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# ============= ERROR HANDLERS =============
@app.errorhandler(400)
def bad_request(error):
    logger.warning(f"Bad request: {error}")
    if request.is_json:
        return jsonify({'error': 'Bad request'}), 400
    flash('Bad request. Please check your input.', 'error')
    return redirect(url_for('dashboard'))


@app.errorhandler(403)
def forbidden(error):
    user = get_current_user()
    if user:
        log_user_action(user.id, 'ACCESS_DENIED', request.url)
    logger.warning(f"Forbidden access attempt: {request.url}")
    
    if request.is_json:
        return jsonify({'error': 'Access forbidden'}), 403
    return render_template('403.html'), 403


@app.errorhandler(404)
def not_found(error):
    logger.warning(f"Not found: {request.url}")
    if request.is_json:
        return jsonify({'error': 'Resource not found'}), 404
    flash('The requested page was not found.', 'error')
    return redirect(url_for('dashboard'))


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    db.session.rollback()
    if request.is_json:
        return jsonify({'error': 'Internal server error'}), 500
    flash('An internal error occurred. Please try again.', 'error')
    return redirect(url_for('dashboard'))


@app.errorhandler(IntegrityError)
def handle_db_integrity_error(error):
    logger.error(f"Database integrity error: {error}")
    db.session.rollback()
    if request.is_json:
        return jsonify({'error': 'Database constraint violation'}), 400
    flash('A database error occurred. This might be due to duplicate data.', 'error')
    return redirect(request.referrer or url_for('dashboard'))

# ============= APP INITIALIZATION =============
def create_app():
    """Application factory pattern."""
    with app.app_context():
        try:
            db.create_all()
            _run_migration()
            logger.info("Application initialized successfully")
        except Exception as e:
            logger.error(f"Application initialization error: {e}")
    return app


if __name__ == '__main__':
    # Initialize the application
    create_app()
    
    # Run in development mode
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV') != 'production'
    
    logger.info(f"Starting EGAS Task Manager on port {port} (debug={debug_mode})")
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
