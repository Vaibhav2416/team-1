
# Authentication and Authorization

# Authentication
# It simply means identifying your user
# With the help of authentication you can access website and perform your task
# SignUp and Login is the example of authentication
# In Authentication we are going to see how user will get verify
    # how password hashing will get performed

# Authorization
# It simply means giving access to routes according role of user



# Authentication

# We will create one app, where user can perform signup, login,
# and able to view dashboard after login, also user will be able to
# logout from the session


# Bcrypt Library
# This will help to convert your plain text into encrypted format
# 123 ---> #$@^^*#$

# pip install flask Flask-SQLAlchemy flask-bcrypt

# Flask-login - this library will manage sessions

from flask import Flask, render_template, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required,logout_user,UserMixin,current_user

app=Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"]="sqlite:///project.db"
app.config["SECRET_KEY"]="welcome" #this is for security purpose
db=SQLAlchemy(app)

# To initialise flask login
# 1. initialise one variable

login_manager=LoginManager()
login_manager.init_app(app)  # we are connecting our app with flask-login
login_manager.login_view="loginFunction" # if user is not authenticated
                                        # then he will be redirected login page
# UserMixin
# This will provide methods like is_authenticated, is_active, get_id()

@app.route("/")
def home():
    return render_template("base.html")

class User(db.Model,UserMixin):
    __tablename__="user"
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(100))
    email=db.Column(db.String(100))
    password_hash=db.Column(db.String(200))  #123
    role=db.Column(db.String,default="user")

    def generate_password(self,simple_password):  #this function is for generating hash password
        self.password_hash=generate_password_hash(simple_password)
    
    def check_password(self, simple_password):
        return check_password_hash(self.password_hash,simple_password)
    

@app.route("/register",methods=["GET","POST"])
def registerFunction():
    if request.method=="POST":
        username=request.form.get("username")
        email=request.form.get("email")
        password=request.form.get("password")

        if User.query.filter_by(email=email).first(): 
            flash("User Already Exists")
            return redirect(url_for("home"))

        user_object=User(username=username,email=email)
        user_object.generate_password(password)  # secret&*$......
        db.session.add(user_object)
        db.session.commit()
        flash("User Registered Successfully")
        return redirect(url_for("loginFunction"))

    return render_template("signup.html")

@app.route("/login",methods=["GET","POST"])
def loginFunction():
    if request.method=="POST":
        email=request.form.get("email")
        password=request.form.get("password")
        user_object=User.query.filter_by(email=email).first()
        
        if user_object and user_object.check_password(password):
            login_user(user_object) #we are storing user in session here
            flash("User Logged in Successfully")
            return redirect(url_for("dashboard"))
        else:
            return "Invalid User"

    return render_template("login.html")

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id)) # this will fetch current
                                            #user data from the database

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")


# Authorization
# Authorization is the process of granting access to user according
# to their roles


def role_required(role): # this function is taking role of user
    def decorator(func): #this function is taking view function as parameter
        def wrapper(*args,**kwargs):
            if current_user.role!=role:
                flash("Unauthorized Access")
                return redirect(url_for("loginFunction"))
            return func(*args,**kwargs)
        return wrapper
    return decorator
            



@app.route("/admin")
@login_required
@role_required("admin")
def admin():
    return render_template("admin.html")


@app.route("/logout")
def logout():
    logout_user()
    flash("User logged out successfully")
    return redirect(url_for("home"))

with app.app_context():  #this will open window for database
    db.create_all()

    if not User.query.filter_by(role="admin").first():
        admin=User(username="admin",email="admin@gmail.com",role="admin")
        admin.generate_password("admin")
        db.session.add(admin)
        db.session.commit()


if __name__=="__main__":
    app.run(debug=True)





