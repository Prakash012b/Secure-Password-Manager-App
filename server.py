#connecting database
#https://www.youtube.com/watch?v=WeslBREciKY&t=153s
#https://www.youtube.com/watch?v=nrG0tKSYMHc&t=295s
#https://www.geeksforgeeks.org/python/flask-app-configuation/app.
#https://flask.palletsprojects.com/en/stable/config/
#https://www.geeksforgeeks.org/python/profile-application-using-python-flask-and-mysql/
#https://github.com/alexferl/flask-mysqldb

#Session permanence (keeping user logged in / session timeout)
#https://stackoverflow.com/questions/37227780/flask-session-persisting-after-close-browser
#https://stackoverflow.com/questions/3024153/how-to-expire-session-due-to-inactivity-in-django
#https://stackoverflow.com/questions/11783025/is-there-an-easy-way-to-make-sessions-timeout-in-flask

#START: CODE COMPLETED BY CHRISTIAN
from flask import Flask, render_template, redirect, url_for, request, session, flash #pip install flask
from flask_mysqldb import MySQL #pip install flask_mysqldb (MUST BE PYTHON 3.11)
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, redirect, request, render_template
from flask import request, jsonify
import os, base64
from datetime import timedelta, datetime

#pip install cryptography
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


#Used to access the Database 
app = Flask(__name__)
app.config['MYSQL_HOST'] = 'mysql.railway.internal'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'tUZrONDQxExptjZmrSkMyBFKxUqYoYbN'
app.config['MYSQL_DB'] = 'railway'
app.config['MYSQL_PORT'] = 3306
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.secret_key = os.urandom(24) #generates random secret key for each user session
mysql = MySQL(app)
#END: CODE COMPLETED BY CHRISTIAN



