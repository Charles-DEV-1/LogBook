# app.py — cleaned & fixed version
from flask import (
    Flask, render_template, session, redirect, request,
    url_for, send_from_directory, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from datetime import datetime, timedelta
import os

# ----- App config -----
app = Flask(__name__)

# Uploads: put uploads inside "static/uploads" so templates can serve via url_for('static', ...)
app.permanent_session_lifetime = timedelta(days=3)
UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')

app.config["UPLOAD_DIRECTORY"] = UPLOAD_FOLDER
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["ALLOWED_EXTENSIONS"] = [".jpg", ".png", ".jpeg", ".gif"]
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
app.config["SECRET_KEY"] = "replace_with_env_secret"  # <- use an env var in production

# Mail config (for production use env vars and App Passwords)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'Cesca1Mul@gmail.com'   # replace or use env var
app.config['MAIL_PASSWORD'] = 'rpqg ctjg vdru zsli'      # replace or use env var
app.config["MAIL_DEBUG"] = True

# Initialize extensions
mail = Mail(app)
db = SQLAlchemy(app)

# ----- Models -----
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    profile_pic = db.Column(db.String(200), nullable=True)  # filename stored
    role = db.Column(db.String(20), nullable=False)  # 'student' or 'supervisor'

    # Student -> Supervisor relation (nullable)
    supervisor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    students = db.relationship(
        "User",
        backref=db.backref("supervisor", remote_side=[id]),
        lazy="dynamic"
    )

    # Relationship with log entries
    log_entries = db.relationship('LogEntry', back_populates='student', lazy="dynamic")

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


class LogEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    task_description = db.Column(db.Text, nullable=False)
    challenges = db.Column(db.Text)
    lessons = db.Column(db.Text)
    hours = db.Column(db.Integer)
    activities = db.Column(db.Text)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    student = db.relationship('User', back_populates='log_entries')

    def __repr__(self):
        return f"<LogEntry {self.id} by student {self.student_id}>"


class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=True)
    entry_id = db.Column(db.Integer, db.ForeignKey("log_entry.id"), nullable=False)
    entry = db.relationship("LogEntry", backref="attachments")

    def __repr__(self):
        return f"<Attachment {self.filename} for {self.entry_id}>"

# ----- Routes -----
@app.route("/")
def index():
    return render_template("index.html")


# ---------- REGISTER ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # get form data
        name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_pass = request.form.get("confirm_pass", "")
        role = request.form.get("role", "student")

        # supervisor_id may be empty -> convert safely
        sup_raw = request.form.get("supervisor_id")
        supervisor_id = int(sup_raw) if sup_raw and sup_raw.isdigit() else None

        # Basic validation
        if not (name and username and email and password):
            flash("Please fill all required fields.", "warning")
            return redirect(url_for("register"))

        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            flash("Username or email already exists!", "warning")
            return redirect(url_for("register"))

        if password != confirm_pass:
            flash("Passwords do not match!", "warning")
            return redirect(url_for("register"))
        if len(password) < 6:
            flash("Password is too weak (min 6 chars).", "warning")
            return redirect(url_for("register"))

        hashed = generate_password_hash(password)

        # handle profile pic
        files = request.files.get("profile_pic")
        profile_pic_filename = None
        filename = None
        try:
            if files and files.filename.strip() != "":
                ext = os.path.splitext(files.filename)[1].lower()
                if ext not in app.config["ALLOWED_EXTENSIONS"]:
                    flash("File type not supported.", "warning")
                    return redirect(url_for("register"))
                filename = secure_filename(files.filename)
                files.save(os.path.join(app.config["UPLOAD_DIRECTORY"], filename))
                profile_pic_filename = filename
            else:
                profile_pic_filename = None  # or default.png if you want
        except RequestEntityTooLarge:
            flash("File Too heavy!","warning")        

        # create user and commit
        user = User(
            name=name,
            username=username,
            email=email,
            password=hashed,
            role=role,
            profile_pic=profile_pic_filename,
            supervisor_id=supervisor_id if role == "student" else None
        )
        db.session.add(user)
        db.session.commit()

        # welcome email (won't stop registration on failure)
        try:
            msg = Message("Welcome to LogMaster", sender=app.config['MAIL_USERNAME'], recipients=[email])
            msg.body = f"Hello {username},\n\nWelcome to LogMaster!"
            mail.send(msg)
        except Exception as e:
            # just log/print; don't fail registration
            print("Email send failed:", e)

        # notify supervisor (if applicable)
        if role == "student" and supervisor_id:
            supervisor = User.query.get(supervisor_id)
            if supervisor:
                try:
                    msg = Message(
                        "New student assigned", sender=app.config['MAIL_USERNAME'],
                        recipients=[supervisor.email]
                    )
                    msg.body = f"Hello {supervisor.username},\n\nA new student ({name}) registered under you."
                    mail.send(msg)
                except Exception as e:
                    print("Supervisor email failed:", e)

        flash("Registration successful — please log in.", "success")
        return redirect(url_for("login"))

    # GET
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    supervisors = User.query.filter_by(role="supervisor").all()
    return render_template("register.html", supervisors=supervisors)


# ---------- LOGIN ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["role"] = user.role
            flash("Login successful.", "success")
            if user.role == "student":
                return redirect(url_for("dashboard"))
            return redirect(url_for("sup_dashboard"))
        flash("Invalid credentials.", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


# ---------- LOGOUT ----------
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


# ---------- STUDENT DASHBOARD ----------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("role") != "student":
        return redirect(url_for("sup_dashboard"))

    user = User.query.get(session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    logs = user.log_entries.order_by(LogEntry.created_at.desc()).all()
    attachments = Attachment.query.order_by(Attachment.entry_id).all()
    return render_template("dashboard.html", logs=logs, user=user, attachments=attachments)


# ---------- SUPERVISOR DASHBOARD ----------
@app.route("/supervisor")
@app.route("/supervisor_dashboard")
def sup_dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    supervisor = User.query.get(session["user_id"])
    if not supervisor or supervisor.role != "supervisor":
        flash("Unauthorized.", "danger")
        return redirect(url_for("dashboard"))

    students = supervisor.students.order_by(User.username).all()
    attachments = Attachment.query.order_by(Attachment.entry_id).all()
    return render_template("supervisor_dashboard.html", students=students, user=supervisor, attachments=attachments)


# ---------- VIEW LOGS (by supervisor for a student) ----------
@app.route("/supervisor/logs/<int:student_id>")
def view_logs(student_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    supervisor = User.query.get(session["user_id"])
    if not supervisor or supervisor.role != "supervisor":
        flash("Unauthorized.", "danger")
        return redirect(url_for("dashboard"))

    student = User.query.get_or_404(student_id)

    # authorization check: student must belong to supervisor
    if student.supervisor_id != supervisor.id:
        flash("You are not authorised to view this student's logs.", "danger")
        return redirect(url_for("sup_dashboard"))

    logs = LogEntry.query.filter_by(student_id=student.id).order_by(LogEntry.created_at.desc()).all()
    attachments = Attachment.query.filter_by(entry_id=student.id).all()
    return render_template("view_logs.html", student=student, logs=logs, attachments=attachments)


# ---------- CREATE ENTRY ----------
# ---------- CREATE ENTRY ----------
@app.route("/entry/new", methods=["GET", "POST"])
def create_entry():
    if "user_id" not in session:
        flash("Please login.", "warning")
        return redirect(url_for("login"))
    if session.get("role") != "student":
        return redirect(url_for("sup_dashboard"))

    if request.method == "POST":
        task_description = request.form.get("task_description", "").strip()
        if not task_description:
            flash("Task description required.", "warning")
            return redirect(url_for("create_entry"))

        challenges = request.form.get("challenges")
        lessons = request.form.get("lessons")
        hours = request.form.get("hours")
        activities = request.form.get("activities")

        # Create the log entry first
        entry = LogEntry(
            student_id=session["user_id"],
            task_description=task_description,
            challenges=challenges,
            lessons=lessons,
            hours=int(hours) if hours and hours.isdigit() else None,
            activities=activities
        )
        db.session.add(entry)
        db.session.commit()  # commit so entry has an ID

        # ---------- Handle Attachments ----------
        files = request.files.getlist("attachments")  # multiple files
        for file in files:
            if file and file.filename.strip() != "":
                ext = os.path.splitext(file.filename)[1].lower()
                if ext not in app.config["ALLOWED_EXTENSIONS"]:
                    flash(f"{file.filename} has unsupported file type.", "warning")
                    continue
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config["UPLOAD_DIRECTORY"], filename))
                attachment = Attachment(filename=filename, entry_id=entry.id)
                db.session.add(attachment)

        db.session.commit()

        # notify supervisor (email as before)
        role = session.get("role")
        user = User.query.get(session["user_id"])
        supervisor_id = user.supervisor_id
        if role == "student" and supervisor_id:
            supervisor = User.query.get(supervisor_id)
            if supervisor:
                try:
                    msg = Message(
                        "New Log Created", sender=app.config['MAIL_USERNAME'],
                        recipients=[supervisor.email]
                    )
                    msg.body = f"Hello {supervisor.username},\n\nYour student {user.name} created a new log. Check your dashboard."
                    mail.send(msg)
                except Exception as e:
                    print("Supervisor email failed:", e)

        flash("Entry created with attachments.", "success")
        return redirect(url_for("dashboard"))

    return render_template("create_entry.html")



# ---------- EDIT ENTRY ----------
@app.route("/entries/<int:id>/edit", methods=["GET", "POST"])
def edit_entry(id):
    if "user_id" not in session:
        flash("Please login.", "warning")
        return redirect(url_for("login"))
    if session.get("role") != "student":
        return redirect(url_for("sup_dashboard"))

    entry = LogEntry.query.get_or_404(id)
    # security: ensure current user owns this entry
    if entry.student_id != session["user_id"]:
        abort(403)

    if request.method == "POST":
        entry.task_description = request.form.get("task_description", entry.task_description)
        entry.challenges = request.form.get("challenges", entry.challenges)
        entry.lessons = request.form.get("lessons", entry.lessons)
        hours = request.form.get("hours")
        entry.hours = int(hours) if hours and hours.isdigit() else None
        entry.activities = request.form.get("activities", entry.activities)
        db.session.commit()
        flash("Entry updated.", "success")
        return redirect(url_for("dashboard"))

    return render_template("edit.html", entry=entry)


# ---------- DELETE ENTRY ----------
# ---------- DELETE ENTRY ----------
@app.route("/entries/<int:id>/delete", methods=["GET", "POST"])
def delete_entry(id):
    if "user_id" not in session:
        flash("Please Login!","warning")
        return redirect(url_for("login"))

    if session.get("role") != "student":
        return redirect(url_for("sup_dashboard"))

    entry = LogEntry.query.get_or_404(id)
    user = User.query.get(session["user_id"])
    attachments = Attachment.query.filter_by(entry_id=entry.id).all()

    if request.method == "POST":
        db.session.delete(entry)
        # delete associated attachments
        for att in attachments:
            db.session.delete(att)
        db.session.commit()
        flash("Entry Deleted Successfully!", "success")
        return redirect(url_for("dashboard"))

    # if GET → show delete confirmation page
    return render_template("delete_entry.html", log=entry, user=user)




# ---------- Serve uploaded files (if needed) ----------
@app.route("/upload/<filename>")
def upload(filename):
    return send_from_directory(app.config["UPLOAD_DIRECTORY"], filename)


# ----- App start -----
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=False)

