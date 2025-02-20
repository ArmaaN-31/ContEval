from flask import Flask, render_template, redirect, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import os
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
import json
from flask import jsonify

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATION"] = False
app.config["SECRET_KEY"] = "Your secret key"

db = SQLAlchemy(app)

bcrypt = Bcrypt(app)
login_manager = LoginManager()

login_manager.init_app(app)
login_manager.login_view = "login"

class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
    mobile = db.Column(db.String(15), nullable=False)
    role = db.Column(db.String(50), nullable=False, default="user")

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password)

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_name = db.Column(db.String(255), nullable=False)
    quiz_data = db.Column(db.String, nullable=False)

    def __repr__(self):
        return f'<Quiz {self.quiz_name}>'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return render_template("home.html", current_user=current_user)

@app.route("/postques")
@login_required
def postques():
    return render_template("post.html", current_user=current_user)

@app.route("/postquesinform", methods=["POST"])
@login_required
def postquesinform():
    try:
        data = request.get_json()
        quiz_name = data.get("quiz_name")
        quiz_data = data.get("quiz_data")

        if not quiz_name or not isinstance(quiz_data, list) or len(quiz_data) == 0:
            return jsonify({"error": "Invalid input data"}), 400

        quiz_data_json = json.dumps(quiz_data)

        new_quiz = Quiz(quiz_name=quiz_name, quiz_data=quiz_data_json)
        db.session.add(new_quiz)
        db.session.commit()

        return jsonify({"message": "Quiz created successfully!"}), 200

    except Exception as e:
        print(f"Error occurred: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/dashboard")
@login_required
def dashboard():
    allquizzes = Quiz.query.all()
    return render_template("dashboard.html", allquizzes=allquizzes)

@app.route("/quizques/<quizid>")
@login_required
def quizques(quizid):
    foundquiz = Quiz.query.get(quizid)
    if foundquiz:
        quiz_data = json.loads(foundquiz.quiz_data)
        return render_template("quiz.html", foundquiz=foundquiz, quiz_data=quiz_data)
    else:
        return "Quiz not found", 404

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role")

        user = User.query.filter_by(email=email, role=role).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials!", "danger")

    return render_template("login.html", current_user=current_user)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        mobile = request.form.get("mobile")

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already exists!", "danger")
            return redirect(url_for("register"))

        new_user = User(name=name, email=email, mobile=mobile)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash("<strong>Registration successful! Please log in.</strong>", "success")
        return redirect(url_for("login"))

    return render_template("/register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for("login"))

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")

@app.route("/about")
def about():
    return render_template("about.html")

if __name__ == "__main__":
    app.run(debug=True)
