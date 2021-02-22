from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = '094j23j4fsdsdfKl;kc' # The secret key enables sessions to be set for authentication
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = "./static/files"
app.config['LOGIN_DISABLED'] = False # Set this to True when unit testing to globally turn off authentication

db = SQLAlchemy(app)



##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    def __init__(self, email, password, name):
        self.email = email
        self.password = password
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password)


#Line below only required once, when creating DB. 
# db.create_all()

# ------ Login Manager object ----------- #
login_manager = LoginManager()

# ---- Configuring the login manager for login ---------- #
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader # providing a user_loader callback. This callback is used to reload the user object from
def load_user(user_id):
    return User.query.get(user_id) # Allows Flask-Login to load the current user and grab their ID, so once someone
# is logged in we'll be able to show them pages specific to their logon ID


@app.route('/')
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email_input = request.form.get('email')
        if User.query.filter_by(email=email_input).first():
            flash("You've already signed up with that email. Log in instead!")
            return redirect(url_for("login"))
        else:
            hash_and_salted_password = generate_password_hash(
                password=request.form.get("password"),
                method="pbkdf2:sha256",
                salt_length=8
            )
            new_user = User(
                email=request.form.get('email'),
                name=request.form.get('name'),
                password=hash_and_salted_password,
            )

            db.session.add(new_user)
            db.session.commit()

            user_object = load_user(new_user.id)
            login_user(user_object)

            return redirect(url_for("secrets", name=new_user.name))

    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    """For GET requests, display the login form.
    For POSTS, login the current user by processing the HTML form inputs

    """
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    # If the user is already logged in, redirect to the home page.

    elif request.method == "POST":
        email_input = request.form.get("email")
        selected_user = User.query.filter_by(email=email_input).first() # Find user database entry via the email entered

        if not selected_user:
            # email does not exist
            flash("No user registered under that email.")  # Error message
            return redirect(url_for("login"))

        password_input = request.form.get("password")
        hashed_password = selected_user.password  # Retrieve the hashed password of the user

        # user_object = load_user(selected_user.id)  # Reloading the user object from the user ID stored in the session.
        # The unicode ID of the user is the input
        # The corresponding user object is the output

        # checking the password entered against a given salted and hashed password value

        if check_password_hash(pwhash=hashed_password, password=password_input):
            # db.session.add(user_object)
            db.session.commit()
            login_user(selected_user)
            flash("Logged in successfully.")
            return redirect(url_for("secrets", name=selected_user.name))
        else:
            # incorrect password
            flash("Password incorrect. Please try again.")
            return redirect(url_for("login"))


    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", name=current_user.name)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download/')
@login_required
def download():
    return send_from_directory(directory=app.config['UPLOAD_FOLDER'], filename="cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
