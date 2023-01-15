from . import app
from functools import wraps
import jwt
from flask import jsonify, request, url_for, redirect
from flask_login import current_user
from datetime import datetime


def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):
       token = request.cookies.get('token')
       if not token:
           return redirect(url_for('logout'))
       try:
           data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
           if data.get('exp') < datetime.utcnow().timestamp():
               return redirect(url_for('logggout'))
           if data.get('user_id') != current_user.id:
                return redirect(url_for('logout'))
       except:
           return redirect(url_for('logout'))
 
       return f(*args, **kwargs)
   return decorator