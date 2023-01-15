from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from notesapp.models import User, Post
from flask_login import current_user
import re
from math import log
from flask_ckeditor import CKEditorField

class  RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirmpassword = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('This username is already taken by another user, please choose antoher one.')

    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('This email is already assigned to another account, please choose antoher one.')


    def validate_password(self, password):
        if re.search(r"\d", password.data) is None:
            raise ValidationError('Password must contain at least one digit.')
        if re.search(r"[A-Z]", password.data) is None:
            raise ValidationError('Password must contain uppercase characters.')
        if re.search(r"[a-z]", password.data) is None:
            raise ValidationError('Password must contain lowercase characters.')
        if re.search(r"\W", password.data) is None:
            raise ValidationError('Password must contain at least one scpecial symbol character.')



class  LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class  UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('This username is already taken by another user, please choose antoher one.')

        
    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('This email is already assigned to another account, please choose antoher one.')


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = CKEditorField('Body')
    #content = TextAreaField('Content', validators=[DataRequired()])
    ispublic = BooleanField('Public')
    isencrypted = BooleanField('Encrypt')
    password = PasswordField('Password')
    submit = SubmitField('Post')


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Reset Password')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            return False

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirmpassword = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

class DecryptNote(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Decrypt')