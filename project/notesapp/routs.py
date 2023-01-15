import secrets, os, hashlib, bleach, blowfish
from PIL import Image
from flask import (render_template, url_for, flash, redirect, 
                    request, abort, make_response)
from . import app, bcrypt, db, mail, hasher
from .forms import (RegistrationForm, LoginForm, UpdateAccountForm, 
                    PostForm, ResetPasswordForm, RequestResetForm, DecryptNote)
from .models import User, Post
from flask_login import (login_user, current_user, logout_user, 
                        login_required)
import jwt, time
from datetime import datetime, timedelta
from .decorators import token_required
from flask_mail import Message
from sqlalchemy import or_
import pprint

login_attempt = 0

@app.route("/")
def default():
    if current_user.is_authenticated:
        return redirect('/home')
    else:
        return redirect('/login')



@app.route("/home")
@token_required
@login_required
def home():
    posts = Post.query.filter(or_(Post.ispublic, Post.user_id.like(current_user.id)))
    return render_template('home.html', posts=posts)

@app.route("/about")
def about():
    return render_template('about.html', title='About')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        #hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        #user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        hashed_passwd = hasher.hash(hashlib.sha256(bytes(form.password.data, 'utf-8')).hexdigest())
        user = User(username=form.username.data, email=form.email.data, password=hashed_passwd)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        time.sleep(1)
        user = User.query.filter_by(email=form.email.data).first()
        #if user and bcrypt.check_password_hash(user.password, form.password.data):
        if user:
            if user.loginattempts <= 5:
                try:
                    hasher.verify(user.password, hashlib.sha256(bytes(form.password.data, 'utf-8')).hexdigest())
                    expire_date = datetime.utcnow() + timedelta(minutes=30)
                    token = jwt.encode({
                        'user_id' : user.id,
                        'exp' : expire_date
                        }, app.config['SECRET_KEY'], algorithm="HS256")
                    login_user(user)
                    resp = make_response(redirect('/home'))
                    resp.set_cookie('token', token, httponly = True, expires=expire_date)
                    user.loginattempts = 0
                    db.session.commit()
                    return resp
                except:
                    user.loginattempts += 1
                    db.session.commit()
                    flash('Login Unsuccessful. Please check username and password', 'danger')
            else:
                user.loginattempts += 1
                db.session.commit()
                flash('Login Unsuccessful. Please check username and password', 'danger')
            if user.loginattempts == 5:
                flash('5 failed login attempts. Your account has been blocked. Reset your password to unlock them.', 'danger')   
        else:
           flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")

def logout():
    logout_user()
    try:
        resp = make_response(redirect('/login'))
        resp.set_cookie('token', "", expires=0)      
    except:
        resp = make_response("User loged out, but error ocured during redirecting. Please refresch", 400)
        resp.set_cookie('token', "")
    return resp

def save_picture(picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(picture.filename)
    picture_fn = str(current_user.id) + "_" + random_hex + f_ext 
    picture_path = os.path.join(app.root_path, 'static/pictures', picture_fn) 

    output_size = (125, 125)
    i = Image.open(picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn

@app.route("/account", methods=['GET', 'POST'])
@token_required
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated', "success")
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    return render_template('account.html', title='Account', form=form)

@app.route("/post/new", methods=['GET', 'POST'])
@token_required
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        content = bleach.clean(form.content.data)
        title = bleach.clean(form.title.data)
        ispublic = form.ispublic.data
        if form.isencrypted.data:
            cipher = blowfish.Cipher(bytes(form.password.data, 'utf-8'))
            content = b"".join(cipher.encrypt_ecb_cts(bytes(content, 'utf-8')))
            ispublic = False
        post = Post(title=title, content=content, author=current_user, isencrypted=form.isencrypted.data, ispublic=ispublic)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title='New Post', form=form, legend='Create Post')

@app.route("/post/<int:post_id>")
@token_required
@login_required
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', title=post.title, post=post)


@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@token_required
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = bleach.clean(form.title.data)
        post.content = bleach.clean(form.content.data)
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == 'GET':         
        form.title.data = post.title
        form.content.data = post.content
    return render_template('create_post.html', title='Update Post', form=form, legend='Update Post')

@app.route("/post/<int:post_id>/decrypt", methods=['GET', 'POST'])
@token_required
@login_required
def decrypt_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = DecryptNote()
    if form.validate_on_submit():
        time.sleep(1)
        cipher = blowfish.Cipher(bytes(form.password.data, 'utf-8'))
        decrypted = b"".join(cipher.decrypt_ecb_cts(post.content))
        post.content = str(decrypted)[2:-1]
        post.isencrypted = False
        return render_template('post.html', title=post.title, post=post)
    return render_template('decrypt_post.html', title='Decrypt Post', form=form, legend='Update Post')



@app.route("/post/<int:post_id>/delete", methods=['GET'])
@token_required
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('home'))

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender='noreplay@demo.com', recipients=[user.email])
    msg.body = f'''To reset password folow this link:
{url_for('reset_password', token=token, _external=True)}
    '''
    mail.send(msg)

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect('/home')
    form  = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        flash("An email has been sent with instructions to reset your password", 'success')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect('/home')
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is invalid token. Your token may expired.', 'warning')
        return redirect(url_for('reset_passord_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash(f'password has been updated!', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', title='Reset Password', form=form)


