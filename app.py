from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask import flash
from sqlalchemy import or_
import os

app = Flask(__name__)

# ---------- DATABASE CONFIG (AZURE POSTGRESQL – FIXED) ----------
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = "supersecretkey"  # change later in production

db = SQLAlchemy(app)

with app.app_context():
    db.create_all()

# ---------- USER MODEL ----------
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    security_question = db.Column(db.String(200), nullable=True)
    security_answer = db.Column(db.String(200), nullable=True)


# ---------- ROUTES ----------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/option")
def option():
    return render_template("options.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        security_question = request.form.get("security_question")
        security_answer = request.form.get("security_answer")

        existing_user = User.query.filter(
            or_(User.username == username, User.email == email)
        ).first()

        if existing_user:
            flash("Username or Email already exists", "error")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)

        hashed_answer = (
            generate_password_hash(security_answer)
            if security_question and security_answer
            else None
        )

        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            security_question=security_question if hashed_answer else None,
            security_answer=hashed_answer
        )

        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form["identifier"]
        password = request.form["password"]

        user = User.query.filter(
            or_(User.username == identifier, User.email == identifier)
        ).first()

        if not user:
            flash("Username or email not found", "error")
            return redirect(url_for("login"))

        if not check_password_hash(user.password, password):
            flash("Incorrect password", "error")
            return redirect(url_for("login"))

        flash("Login successful!", "success")
        return redirect(url_for("home"))

    return render_template("login.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    user = None
    security_question = None
    error_message = None

    if request.method == "POST":
        identifier = request.form.get("identifier")

        if "check_user" in request.form:
            user = User.query.filter(
                or_(User.username == identifier, User.email == identifier)
            ).first()

            if not user or not user.security_question:
                error_message = "Password reset not available for this account"
            else:
                security_question = user.security_question

        elif "reset_password" in request.form:
            answer = request.form["security_answer"]
            new_password = request.form["new_password"]

            user = User.query.filter(
                or_(User.username == identifier, User.email == identifier)
            ).first()

            if not user or not user.security_answer:
                error_message = "Invalid password reset request"
            elif not check_password_hash(user.security_answer, answer):
                security_question = user.security_question
                error_message = "Incorrect security answer"
            else:
                user.password = generate_password_hash(new_password)
                db.session.commit()
                flash("Password reset successful! Please login.", "success")
                return redirect(url_for("login"))

    return render_template(
        "password_reset.html",
        user=user,
        security_question=security_question,
        error_message=error_message
    )


# ---------- RUN ----------
if __name__ == "__main__":
    app.run(debug=True, use_reloader=False, port=8000)

