from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
import argon2
from flask_ckeditor import CKEditor
from flask_wtf.csrf import CSRFProtect



app = Flask(__name__)
app.config['SECRET_KEY'] = 'ece17fdfa8d813c829d04933055ea85a'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
loginmanager = LoginManager(app)
loginmanager.login_view = 'login'
loginmanager.login_message_category = 'info'
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = ''    ### add your username
app.config['MAIL_PASSWORD'] = ''    ### add your app password
mail = Mail(app)
hasher = argon2.PasswordHasher(
    time_cost=3, # number of iterations
    memory_cost=64 * 1024, # 64mb
    parallelism=8, # how many parallel threads to use
    hash_len=16, # the size of the derived key
    salt_len=32 # the size of the random generated salt in bytes
)
ckeditor = CKEditor(app)
csrf = CSRFProtect(app)


from notesapp import routs