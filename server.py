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
#https://stackoverflow.com/questions/27281216/how-can-i-keep-field-values-in-a-form-after-submit

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
#https://cryptography.io/en/latest/fernet/
#https://www.geeksforgeeks.org/python/fernet-symmetric-encryption-using-cryptography-module-in-python/

#password hashing
#https://werkzeug.palletsprojects.com/en/stable/utils/#werkzeug.security.generate_password_hash
#https://thepythoncode.com/article/build-a-password-manager-in-python
#https://zetcode.com/python/os-urandom/

#NAVBAR/Styling
#https://getbootstrap.com/docs/5.0/components/navbar/

#Flash
#https://flask.palletsprojects.com/en/stable/patterns/flashing/
#https://stackoverflow.com/questions/44569040/change-color-of-flask-flash-messages

#2FA Verification
#https://www.freecodecamp.org/news/how-to-implement-two-factor-authentication-in-your-flask-app/#heading-how-to-add-the-setup-2fa-page

#START: CODE COMPLETED BY CHRISTIAN
from flask import Flask, render_template, redirect, url_for, request, session, flash #pip install flask
from flask_mysqldb import MySQL #pip install flask_mysqldb (MUST BE PYTHON 3.11)
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, redirect, request, render_template
from flask import request, jsonify
import os, base64
from datetime import timedelta, datetime
import re
import pyotp #One-time password library
import qrcode #Generate QR code
from io import BytesIO

#pip install cryptography
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


#Used to access the Database 
app = Flask(__name__, template_folder='templates')
app.config['MYSQL_HOST'] = 'turntable.proxy.rlwy.net'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'tUZrONDQxExptjZmrSkMyBFKxUqYoYbN'
app.config['MYSQL_DB'] = 'railway'
app.config['MYSQL_PORT'] = 11731
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

def emailExists(email):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    return user


#Used to create a derivation key using the user's master password and salt value. (Uses SHA-256 and PBKDF2 to create it)
def derivationKey(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode())) #This key is used to encrypt/decrypt user account passwords
    return key


@app.route("/")
def home():
    return redirect(url_for("login"))


#Register Function
@app.route("/register", methods = ["GET", "POST"])
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
        fullName = request.form["fullName"]
        email = request.form["email"]
        password = request.form["password"]
        hashPass = generate_password_hash(password) #Hashes the current password using scrypt. Automatically applies a salt length of 16
        salt = os.urandom(16) #generates random string for salt for user's derivation key

        #Input Validation for Email
        if not emailValidation(email):
            flash("Email is in an invalid format (Email Format: xx@yy.com or abc.def@123.co.uk )", 'error')
            return render_template("register.html", fullName = fullName, email = email)
        
        elif emailExists(email):
            flash("Email is already registered", 'error')
            return render_template("register.html", fullName = fullName, email = email)
        
        #Password Validation (Contains 1 upper/lowercase letter, number, special character and between 15-30 characters)
        elif re.search(r'[0-9]', password) is None:
            flash("Password has to contain atleast 1 number.")
            return render_template("register.html", fullName = fullName, email = email)
            
        elif re.search(r'[a-z]', password) is None:
            flash("Password has to contain atleast 1 lowercase letter.")
            return render_template("register.html", fullName = fullName, email = email)

        elif re.search(r'[A-Z]', password) is None:
            flash("Password has to contain atleast 1 uppercase letter.")
            return render_template("register.html", fullName = fullName, email = email)

        elif re.search(r'[$%@#!?%*]', password) is None:
            flash("Password has to contain atleast 1 special character.")
            return render_template("register.html", fullName = fullName, email = email)

        elif len(password) < 15 or len(password) > 30:
            flash("Password has to be between 15 and 30 characters.")
            return render_template("register.html", fullName = fullName, email = email)

        else:
            cursor = mysql.connection.cursor()
            cursor.execute("INSERT into users (fullName, email, password_hash, salt) VALUES (%s, %s, %s, %s)", (fullName, email, hashPass, salt))
            mysql.connection.commit()

            flash("Account successfully created!")
            return render_template("register.html")





#Code by Prakash and Christian
#Login Function with 2FA
@app.route("/login", methods=["GET", "POST"])
def login():

    #If the user is login then prevents from re-login and redirect to account page
    if "user_id" in session:
        flash("You are already logged in", "warning")
        return redirect(url_for("accountPage"))

    #If the request is GET show the login page
    if request.method == "GET":
        return render_template("login.html")

    #Post request- extract email and password from submitted form
    email = request.form["email"]
    password = request.form["password"]

    #Query the database to find the user by email
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()
    cursor.close()

    #uses 'check_password_hash' to safely compare hashed password
    if not user or not check_password_hash(user["password_hash"], password):
        flash("Invalid email or password", "error")
        return render_template("login.html")

    # Store temporarily before 2FA verification
    session["pending_user_id"] = user["id"]
    session["pending_password"] = password

    # If no TOTP secret, generate and store it in session (don't rely on DB fetch timing)
    if not user["totp_secret"]:
        totp_secret = pyotp.random_base32()
        session["temp_totp_secret"] = totp_secret  # use this for first login
       
       #save the generated password secret into DB
        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE users SET totp_secret=%s WHERE id=%s", (totp_secret, user["id"]))
        mysql.connection.commit()
        cursor.close()
    else:
        #If user already has a secret, reuse it so their authenticator app still works
        session["temp_totp_secret"] = user["totp_secret"]

    return redirect(url_for("verify_2fa"))

#Code by Prakash and Christian



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("login"))
  
#END: CODE COMPLETED BY CHRISTIAN

#START: CODE COMPLETED BY PRAKASH

# Route to display all saved accounts for the logged-in user
@app.route("/accountPage")
def accountPage():
    # Check if the user is logged in
    if "user_id" not in session:
        flash("Please log in first", "error")
        return redirect(url_for("login"))

 # Fetch all accounts for the current user from the database
    cursor = mysql.connection.cursor()
    cursor.execute(
        "SELECT id, title, account_email, password_encrypted FROM accounts WHERE user_id = %s",
        (session["user_id"],),
    )
    accounts = cursor.fetchall() # Get all account records as a list of dictionaries
    cursor.close()

    # Decrypt passwords using the user's session key
    key = session.get("key")# Retrieve encryption key from session
    f = Fernet(key)     # Initialize Fernet encryption
    for acc in accounts:
        try:
            # Decrypt the password
            acc["password_encrypted"] = f.decrypt(acc["password_encrypted"]).decode()
        except Exception:
            # If decryption fails, show an error message instead
            acc["password_encrypted"] = "[Error decrypting]"

    return render_template("accountPage.html", accounts=accounts)

# Route to add a new account
@app.route("/addAccount", methods=["GET", "POST"])
def addAccount():
    # Check if the user is logged in
    if "user_id" not in session:
        flash("Please log in first", "error")
        return redirect(url_for("login"))

     # Handle form submission
    if request.method == "POST":
        title = request.form["title"]
        account_email = request.form["account_email"]
        password_plain = request.form["password_plain"]

        key = session.get("key")
        if not key:
             # If the key is missing, session expired
            flash("Session expired, please log in again.", "danger")
            return redirect(url_for("login"))


        # Encrypt the password before saving
        f = Fernet(key)
        password_encrypted = f.encrypt(password_plain.encode())

        # Insert the new account into the database
        cursor = mysql.connection.cursor()
        cursor.execute(
            """
            INSERT INTO accounts (user_id, title, account_email, password_encrypted)
            VALUES (%s, %s, %s, %s)
            """,
            (session["user_id"], title, account_email, password_encrypted),
        )
        mysql.connection.commit()
        cursor.close()

        flash("New account added successfully!", "success")
        return redirect(url_for("accountPage"))

    # If GET request, just render the add account form
    return render_template("addAccount.html")


def generate_salt() -> bytes:
    return os.urandom(16)



@app.route("/decrypt_account", methods=["POST"])
def decrypt_account():
    data = request.get_json()
    account_id = data.get("account_id")

    if "user_id" not in session:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401

    user_id = session["user_id"]

    # Fetch user's salt
    cursor = mysql.connection.cursor(dictionary=True)
    cursor.execute("SELECT salt FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()
    if not user:
        cursor.close()
        return jsonify({"ok": False, "error": "User not found"}), 404

    

    # Derive key from master password
    try:
        key = session["key"]
        f = Fernet(key)
    except Exception:
        cursor.close()
        return jsonify({"ok": False, "error": "Key derivation failed"}), 500

    # Fetch account password
    cursor.execute("SELECT password_encrypted FROM accounts WHERE id=%s AND user_id=%s",
                   (account_id, user_id))
    acc = cursor.fetchone()
    cursor.close()
    if not acc:
        return jsonify({"ok": False, "error": "Account not found"}), 404

    # Try decrypting
    try:
        password_plain = f.decrypt(acc["password_encrypted"]).decode()
        return jsonify({"ok": True, "password": password_plain})
    except Exception:
        return jsonify({"ok": False, "error": "Invalid master password"}), 403



# Generates a new 2FA secret
def generate_2fa_secret():
    return pyotp.random_base32()  # 16-char secret

# Helper function to generate QR code in base64
def qr_code_base64(uri):
    img = qrcode.make(uri) #create QR code from the provided URI
    buffered = BytesIO() # Create an in-memory buffer to store the image
    img.save(buffered, format="PNG")
    return base64.b64encode(buffered.getvalue()).decode()

# Setup 2FA route
@app.route("/setup_2fa")
def setup_2fa():
    #makes sure the user is logged in
    if "user_id" not in session:
        return redirect(url_for("login"))

#grab user email and existing TOTP secret from the database
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT email, totp_secret FROM users WHERE id=%s", (session["user_id"],))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        flash("User not found", "danger")
        return redirect(url_for("accountPage"))

    # Generate secret only if it doesn't exist
    if not user["totp_secret"]:
        totp_secret = pyotp.random_base32()
        cursor = mysql.connection.cursor()
        cursor.execute("UPDATE users SET totp_secret=%s WHERE id=%s", (totp_secret, session["user_id"]))
        mysql.connection.commit()
        cursor.close()
    else:
        totp_secret = user["totp_secret"]

    # Store in session temporarily for verification
    session["temp_totp_secret"] = totp_secret

    # Generate QR code
    totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(name=user["email"], issuer_name="Secure Password Manager")
    qr_b64 = qr_code_base64(totp_uri)

    # Generate **current 6-digit code** for display
    totp = pyotp.TOTP(totp_secret)
    current_code = totp.now()

    return render_template(
        "setup_2fa.html",
        qr_b64=qr_b64,
        totp_secret=totp_secret,
        current_code=current_code  # <-- pass this to HTML
    )




#END: CODE COMPLETED BY PRAKASH

  
#makes it so that it only runs the app when executed
if __name__ == "__main__":
    app.run(debug=True) #updates in real-time + shows bugs / errors on CMD

