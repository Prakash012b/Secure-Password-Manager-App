#SOURCES

#Connecting to the Database
#https://www.youtube.com/watch?v=WeslBREciKY&t=153s
#https://www.youtube.com/watch?v=nrG0tKSYMHc&t=295s
#https://www.geeksforgeeks.org/python/flask-app-configuation/app.
#https://flask.palletsprojects.com/en/stable/config/
#https://www.geeksforgeeks.org/python/profile-application-using-python-flask-and-mysql/
#https://github.com/alexferl/flask-mysqldb

#Session Permanence (keeping user logged in / session timeout)
#https://stackoverflow.com/questions/37227780/flask-session-persisting-after-close-browser
#https://stackoverflow.com/questions/3024153/how-to-expire-session-due-to-inactivity-in-django
#https://stackoverflow.com/questions/11783025/is-there-an-easy-way-to-make-sessions-timeout-in-flask

#Input Validations
#https://www.geeksforgeeks.org/check-if-email-address-valid-or-not-in-python/
#https://stackoverflow.com/questions/65915695/how-do-i-make-sql-python-find-if-a-full_name-is-already-in-the-database
#https://python-forum.io/thread-7016.html
#https://www.geeksforgeeks.org/python/password-validation-in-python/

#Register / Login Pages 
#https://tedboy.github.io/flask/generated/werkzeug.check_password_hash.html 
#https://stackoverflow.com/questions/46723767/how-to-get-current-user-when-implementing-python-flask-security - returning a full_name
#https://stackoverflow.com/questions/59380641/how-to-display-full_name-in-multiple-pages-using-flask
#https://www.youtube.com/watch?v=fOj16SIa02U&list=LL&index=4
#https://www.youtube.com/watch?v=zjvfeho2890&list=LL&index=5

#Password Validation
#https://www.geeksforgeeks.org/python/password-validation-in-python/
#https://stackoverflow.com/questions/41117733/validation-of-a-password-python
#https://medium.com/@ryan_forrester_/building-a-password-strength-checker-in-python-6f723d20511d

#Creation of derivation key
#https://stackoverflow.com/questions/61985537/symmetric-encryption-using-fernet-in-python-master-password-use-case


#START: CODE COMPLETED BY CHRISTIAN
from flask import Flask, render_template, redirect, url_for, request, session, flash #pip install flask
from flask_mysqldb import MySQL #pip install flask_mysqldb (MUST BE PYTHON 3.11)
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, redirect, request, render_template
from flask import request, jsonify
import os, base64
from datetime import timedelta, datetime
import re

#pip install cryptography
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


#Used to access the Database 
app = Flask(__name__, template_folder='templates')
app.config['MYSQL_HOST'] = 'mysql.railway.internal'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'tUZrONDQxExptjZmrSkMyBFKxUqYoYbN'
app.config['MYSQL_DB'] = 'railway'
app.config['MYSQL_PORT'] = 3306
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.secret_key = os.urandom(24) #generates random secret key for each user session
mysql = MySQL(app)

#Extensions used when uploading files
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')

#Validation definitions
#Email format: x@y.com or abc.def@123.co.uk
def emailValidation(email):
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email)

def email_exists(email):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM Users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    return user


#Used to  encrypt / decrypt passwords (Uses SHA-256 and PBKDF2 to encrypt it)
def derivationKey(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("register", methods = ["GET", "POST"])
def register():
    #Prevents any errors with user registering whilst signed in
    if "user_id" in session:
        flash("You must log out to create another account", 'error')
        return redirect(url_for("accountPage"))
    
    #displays register page
    if request.method == "GET":
        return render_template("register.html")
    
    else:
        #Grabs the user's input information and makes it into variables
        fullName = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        hashPass = generate_password_hash(password)
        salt = os.urandom(16) #generates random string for salt

        #Input Validation for Email
        if not emailValidation(email):
            flash("Email is in an invalid format (Email Format: xx@yy.com or abc.def@123.co.uk )", 'error')
            return redirect(url_for("register"))
        
        elif email_exists(email):
            flash("Email is already registered", 'error')
            return redirect(url_for("register"))
        
        #Password Validation (Contains 1 upper/lowercase letter, number, special character and between 8-30 characters)
        elif password.search(r'[0-9]', password) is None:
            flash("Password has to contain atleast 1 letter.")
            
        elif password.search(r'[a-z]', password) is None:
            flash("Password has to contain atleast 1 lowercase letter.")

        elif password.search(r'[A-Z]', password) is None:
            flash("Password has to contain atleast 1 uppercase letter.")

        elif password.search(r'[$%@#!?%*]', password) is None:
            flash("Password has to contain atleast 1 special character.")

        elif password.search(r'.{8,30}', password) is None:
            flash("Password has to be between 8 and 30 characters.")

        cursor = mysql.connection.cursor()
        cursor.execute("INSERT into users (fullName, email, password_hash, salt) VALUES (%s, %s, %s, %s)", fullName, email, hashPass, salt)
        mysql.connection.commit()

    return render_template("register.html")

@app.route("/login", methods = ["GET", "POST"])
def login():
    #Prevents any errors with user registering whilst signed in
    if "user_id" in session:
        flash("You are already logged in", "warning")
        return redirect(url_for("accountPage"))
    
    if request.method == "GET":
        return render_template("login.html")
    
    else:
        email = request.form["email"]
        password = request.form["password"]

        #Used to grab every user with the specific email typed in (storing session / user id)
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users Where email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()

        #Input Validation
        if not email or not password:
            flash("You must input an email and password to login.", 'error')
        
        elif not user:
            flash("Invalid email address", 'error')
        
        #compares if the password in the input field is equal to the hashed password
        elif not check_password_hash(user["password"], password):
            flash("Invalid password", 'error')

        else:
            #Stores the user's session so that it doesn't log them out if they navigate to another page
            session["user_id"] = user["user_id"]
            session["fullName"] = user["fullName"]
            session["email"] = user["email"]
            session["salt"] = user["salt"]
            session["key"] = derivationKey(password, user["salt"]) #Used for Encrypting/Decrypting account passwords
            


