from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField,TextAreaField
from wtforms.validators import DataRequired,InputRequired,Length,Regexp

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class UserForm(FlaskForm):
    username=StringField('Username',validators=[DataRequired(),Length(min=6,max=15),Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0,
                                              'Usernames must start with a letter and must have only letters, numbers, dots or underscores')])
    email=StringField('Email',validators=[DataRequired()])
    pass_hash=PasswordField('Password',validators=[InputRequired(),Length(min=8,max=15)])


class forgot(FlaskForm):
    username=StringField('Username',validators=[DataRequired(),Length(min=5,max=15)])
    password=PasswordField('Password',validators=[InputRequired(),Length(min=8,max=15)])
    confirm_password=PasswordField('Confirm Password',validators=[InputRequired(),Length(min=8,max=15)])

class Mailsome(FlaskForm):
    sender=StringField('Sender',validators=[InputRequired(),Length(min=8,max=30)])
    recipients=StringField('Recipients',validators=[InputRequired(),Length(min=8)])
    subject=StringField('Subject',validators=[InputRequired()])
    message=TextAreaField('Message',validators=[InputRequired()])

class addnote(FlaskForm):
    subject= StringField('subject',validators=[DataRequired()] ,render_kw={'class':'form-control'})
    note=TextAreaField('note',validators=[DataRequired() ],render_kw={'class':'form-control'})