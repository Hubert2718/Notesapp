from . import db, loginmanager, app
from datetime import datetime
from flask_login import UserMixin
import jwt
from datetime import datetime, timedelta


@loginmanager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(200), nullable=False)
    loginattempts = db.Column(db.Integer, default=0)
    #salt = db.Column(db.String(60), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)

    def get_reset_token(self, expires_sec=1800):
        token = jwt.encode({
            'user_id' : self.id,
            'exp' : datetime.utcnow() + timedelta(seconds=expires_sec)
            }, app.config['SECRET_KEY'], algorithm="HS256")
        return token

    @staticmethod
    def verify_reset_token(token):
        try:
          data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"]) 
          user_id = data.get("user_id")
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(20), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    isencrypted = db.Column(db.Boolean, default=False)
    ispublic = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"