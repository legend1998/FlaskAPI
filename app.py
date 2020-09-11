from datetime import datetime,timedelta
from flask import Flask,render_template,render_template,flash,redirect,url_for,request,jsonify,make_response
from forms import LoginForm,UserForm,forgot,Mailsome,addnote
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.declarative import declarative_base
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import LoginManager,login_required,login_user,logout_user,login_manager,UserMixin,current_user
from flask_admin import Admin,AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_mail import Mail,Message
from flask_dance.contrib.linkedin import make_linkedin_blueprint ,linkedin
from flask_dance.consumer.storage.sqla import OAuthConsumerMixin,SQLAlchemyStorage
from flask_dance.consumer import oauth_authorized
from sqlalchemy.orm.exc import NoResultFound
from flask_bootstrap import Bootstrap
import os,uuid,jwt
from functools import wraps


app=Flask(__name__,static_url_path='/static')  #app initialization


# environmental requirements changes for doing tasks


os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app.config['SECRET_KEY']='verysecretnoonecanknowit'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///db.sqlite3'
app.config.update(
	MAIL_SERVER='smtp.gmail.com',
	MAIL_PORT=465,
	MAIL_USE_SSL=True,
    MAIL_USE_TLS=False,
	)


# for authentication by linkedin we need to make a blueprint which includes id and secret keys of using linkedin API

blueprint = make_linkedin_blueprint(
    client_id="81tk3h8swqr0cw",
    client_secret="oZX4ksnP3igoZRvJ",
    scope=["r_liteprofile"],   # scopes for what type of data we are accessing in this case profile
)


# register app for blueprint , database and mail 

app.register_blueprint(blueprint,url_prefix="/linked_login")
db=SQLAlchemy(app)
mail=Mail(app)


# classes we used in authentication user class have all information
# is_admin is for checking that whether the user is admin or not (role based Authentication)

class User(db.Model,UserMixin):

    id=db.Column(db.Integer,primary_key=True)
    public_id=db.Column(db.String(50),unique=True)
    username=db.Column(db.String(50),unique=True)
    pass_hash=db.Column(db.String(80))
    email=db.Column(db.String(50))
    is_admin=db.Column(db.Boolean(),default=False)
    notes=db.relationship('Notes',backref='owner')


# if any user logged in with linkedin ,he/she is also the user of our site so the data shoud 
# be linked with our class User and keep record of linkedin user

class OAuth(db.Model,OAuthConsumerMixin):
    user_id=db.Column(db.Integer,db.ForeignKey(User.id))
    user=db.relationship(User)


# our Site APi concept = here you can store your class notes or any subject type notes 
# every user has its own notes

class Notes(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    subject=db.Column(db.String(80))
    note=db.Column(db.String(200))
    datetime=db.Column(db.String(200),default=datetime.utcnow())
    owner_id=db.Column(db.Integer,db.ForeignKey(User.id))

# the blueprint storage is for any user log in with linked than it will store the its data as username
# login time etc and provide a session

blueprint.storage=SQLAlchemyStorage(OAuth,db.session,user=current_user,user_required=False)

# to handling the login and login facility the loginManager are required in app

login_manager=LoginManager()
login_manager.init_app(app)

# if user is not logged in than it will redirect to login to page to ask for login
login_manager.login_view='login'

# Controller class is used with modelview find out the authenticated user is Admin or not
# if user is admin it will return True else False means not admin so not able to access admin panel

class Controller(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin
    
    def inaccessible_callback(self,name,**kwargs):
        return redirect(url_for('login'))


# Myadminindexview is responsible for admin panel view 
# if user is not admin than the view is blocked for that user

class MyadminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

admin=Admin(app,index_view=MyadminIndexView())
admin.add_view(Controller(User,db.session))


# loginmanager.usrloaded loads the current_user logged in with its user_id

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# this app for decodeing name from linkedin response json file as firstname and last name

def getname(multistring):
    preferred=multistring['preferredLocale']
    locale="{language}_{country}".format(
        language=preferred["language"],country=preferred['country']
    )
    return multistring["localized"][locale]

# if user click on the button sign in with linkedin 
# the user will log in with linkedin profile

@app.route('/linkedin')
def Linkedin():
    if not linkedin.authorized:
        return redirect(url_for("linkedin.login"))
    resp = linkedin.get("me")
    data=resp.json()
    name="{first} {last}".format(
        first=getname(data["firstName"]),
        last=getname(data["lastName"])
    )
    flash('Logged in successfully','success')
    return redirect(url_for('index'))



# IT is for every user must go through via this method before logging in with linkedin
# it takes linkedin blueprint and loads the response sent by linkedin and use it store name
# of the user and login the user 

@oauth_authorized.connect_via(blueprint)
def linkedin_logged_in(blueprint,token):
    resp = blueprint.session.get("me")
    if resp.ok:
        data=resp.json()
        name="{first} {last}".format(
            first=getname(data["firstName"]),
            last=getname(data["lastName"])
        )
        username=name
        query=User.query.filter_by(username=username)
        try:
            user=query.one()
        except NoResultFound:
            user=User(username=username,pass_hash="null",email="linkedin user")
            db.session.add(user)
            db.session.commit()
        login_user(user)


# this is for securing our api which handles user who restricted for normal user
#it generates token ,as any user is logged in with api than a token is provided for only 30 mins
# after that he can't access the API
def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'x-access-token' in request.headers:
            token=request.headers['x-access-token']
        
        if not token:
            return jsonify({'message':'Token is missing!'}),401
        
        try:
            data=jwt.decode(token,app.config['SECRET_KEY'])
            current_user=User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message':'Token is invalid or missing token login to get token'}),401
        return f(current_user,*args,**kwargs)
    return decorated


@app.context_processor
def context_processor():
    if current_user.is_active:
        return dict(user=current_user)
    return dict(user="")


# homeview

@app.route('/')
def index():
    return render_template('base.html')


#login route view 


#MAIL PAGE
@app.route('/mail',methods=["GET",'POST'])
def sendmail():
    mailform=Mailsome()
    if mailform.validate_on_submit():
        try:
            msg=Message(mailform.message.data,sender=mailform.sender.data,recipients=[mailform.recipients.data])
            mail.send(msg)
            flash('mail sent successfully','success')
        except:

            flash('mail is not sent something went wrong','danger')
        return redirect(url_for('sendmail'))
    return render_template('mail.html',form=mailform)

#PROJECTS PAGE 
@app.route('/projects')
def projects():
    return render_template("projects.html")

@app.route('/login',methods=['GET','POST'])
def login():
    form =LoginForm()
    if form.validate_on_submit():
        query=User.query.filter_by(username=form.username.data)
        try:
            user =query.one()
        except NoResultFound:
            flash("no user is registered with this name","danger")
            return redirect(url_for('index'))
        
        if check_password_hash(user.pass_hash,form.password.data):
            login_user(user,remember=form.remember_me.data)
            flash("logged in successfully","success")
            return redirect(url_for('index'))
        else:
            flash("incorrect passoword or username",'danger')
            return render_template('login.html',form=form)
    return render_template('login.html',form=form)

# Signup page view

@app.route('/signup',methods=['GET','POST'])
def signup():
    form=UserForm()
    if form.validate_on_submit():
        hashed_password=generate_password_hash(form.pass_hash.data)
        user=User(public_id=str(uuid.uuid4()),username=form.username.data,pass_hash=hashed_password,email=form.email.data)
        db.session.add(user)
        db.session.commit()
        flash('Registered successfully','success')
        return redirect(url_for('index'))
    return render_template('signup.html',tittle='Sign Up',form=form)

# forgot password view

@app.route('/forgot_password',methods=['GET','POST'])
def forgot_password():
    form=forgot()
    if form.validate_on_submit():
        if(form.password.data==form.confirm_password.data):
            user=User.query.filter_by(username=form.username.data).first()
            if user:
                user.pass_hash=generate_password_hash(form.password.data)
                db.session.commit()
                flash("password changed successfully",'success')
                return redirect(url_for('login'))
            else :
                flash("user not exist","danger")
                return redirect(url_for('forgot_password'))
        else:
            flash("password mismatch","danger")
            return render_template('forgot_password.html',form=form)
    return render_template('forgot_password.html',form=form)



# APi view page

@app.route('/api',methods=['GET','POST'])
@login_required
def api():
    form =addnote()
    if form.validate_on_submit():
        note=Notes(subject=form.subject.data,note=form.note.data,owner=current_user)
        db.session.add(note)
        db.session.commit()
        flash("note is added.","success")
        return redirect(url_for('api'))
    notes= Notes.query.filter_by(owner=current_user)
    output=[]
    i=1
    for noties in notes:
        note_data={}
        note_data['subject']=noties.subject
        note_data['note']=noties.note
        note_data['id']=i
        note_data['delete_id']=noties.id
        note_data['datetime']=noties.datetime[:-7]
        output.append(note_data)
        i+=1
    
    return render_template('api.html',notes=output,form=form)


@app.route('/deletenote/<int:id>')
def deletenote(id):
    note=Notes.query.filter_by(id=id).one()
    db.session.delete(note)
    db.session.commit()
    return redirect(url_for('api'))
# when clicked in log out the user will go through this route and log out from the session

@app.route('/logout')
def logout():
    logout_user()
    flash('you have been logged out successfully','success')
    return redirect(url_for('index'))

# Creator Page

@app.route('/aboutme')
def about():
    return render_template('about.html')

@app.route('/my/second_assignment')
@login_required
def download2():
    return redirect('https://drive.google.com/open?id=1Riw7h0vnHe5wvF93DeZ17wmnysS8TmNn')

@app.route('/my/first_assignment')
@login_required
def download1():
    return redirect('https://drive.google.com/open?id=1r5isHBZrsMwFkmUzOhuaWAn8rTZoO55F')

@app.route('/my/third_assignment')
@login_required
def download3():
    return redirect('https://drive.google.com/open?id=1ncOaaPux56X7gJMeDFrrJyP_noplb-yJ')




"""


            API for this site
            
            
            
 """

# api route /api/user GET request will provide all the user registered in this


@app.route('/api/user',methods=['GET'])
@token_required
def get_all_user(current_user):
    if not current_user.is_admin: # if the user is not admin user will can.t access this operation
        return jsonify({'message':'you are not authorized to perform this operation'})
    users=User.query.all()
    output=[]
    for user in users:
        user_data={}
        user_data["public_id"]=user.public_id
        user_data["name"]=user.username
        user_data["password"]=user.pass_hash
        user_data["email"]=user.email
        user_data["Admin"]=user.is_admin
        output.append(user_data)
    return jsonify({"users":output})


#every user has public_key of his own using this user can fetch his information 
# only for admin

@app.route('/api/user/<string:public_id>',methods=['GET'])
@token_required
def get_one_user(current_user,public_id):
    if not current_user.is_admin:
        return jsonify({'message':'you are not authorized to perform this operation'})

    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message":"no user in the database"})
    user_data={}
    user_data["public_id"]=user.public_id
    user_data["name"]=user.username
    user_data["password"]=user.pass_hash
    user_data["email"]=user.email
    user_data["Admin"]=user.is_admin
    return jsonify({"user":user_data})


# any user can register himself using this route : /api/user POST method with the information

@app.route('/api/user',methods=['POST'])
@token_required
def create_user(current_user):
    data=request.get_json()
    query=User.query.filter_by(email=data['email']).first()
    if not query:
        return jsonify({"message":"user already exist"})
    hashed_password=generate_password_hash(data["password"])
    user=User(public_id=str(uuid.uuid4()),username=data['name'],pass_hash=hashed_password,email=data['email'],is_admin=False)
    db.session.add(user)
    db.session.commit()
    return jsonify({"message":"new user created"})



# user can promote himself to admin using this
# only for admin


@app.route('/api/user/<public_id>',methods=["PUT"])
@token_required
def promote_user(current_user,public_id):
    if not current_user.is_admin:
        return jsonify({'message':'you are not authorized to perform this operation'})

    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message":"no user in the database"})
    user.is_admin=True
    db.session.commit()
    return jsonify({"message":"user is promoted"})


# delete user  using his public_id
# only for admin

@app.route('/api/user/<public_id>',methods=["DELETE"])
@token_required
def delete_user(current_user,public_id):
    if not current_user.is_admin:
        return jsonify({'message':'you are not authorized to perform this operation'})

    user=User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message":"no user in the database"})
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message":"user is deleted"})

#login with API providing authentications

@app.route('/api/login')
def api_login():
    auth=request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('could not verify',401,{"WWW-Authenticate: login required"})
    user= User.query.filter_by(username=auth.username).first()
    if not user:
        return make_response('could not verify',401,{"WWW-Authenticate: login required"})
    
    if check_password_hash(user.pass_hash,auth.password):
        token=jwt.encode({'public_id':user.public_id,"exp":datetime.utcnow()+timedelta(minutes=30)},app.config['SECRET_KEY'])
        return jsonify({"token":token.decode('UTF-8')})
    
    return make_response('could not verify',401,{"WWW-Authenticate: login required"})




"""

here is note API of our site 
accessible for all user 
registerd 


"""
# create note using this route and and method


@app.route('/noteapi',methods=["POST"])
@token_required
def create_notes(current_user):
    data=request.get_json()
    note=Notes(subject=data['subject'],note=data['note'],owner=current_user)
    db.session.add(note)
    db.session.commit()
    return jsonify({'message':"note is added successfully."})


# get all the notes on the particular subject 
# provide subject name  to API

@app.route('/noteapi/<subject>',methods=['GET'])
@token_required
def get_note_on_subject(subject,current_user):
    notes = Notes.query.filter_by(subject=subject).all()
    if not notes:
        return jsonify({"message":" not notes for this subject"})
    output=[]
    for noties in notes:
        output.append(noties.note)
    return jsonify({"notes":output})


# get all notes on this sites of the current user
# or yours

@app.route('/noteapi/all',methods=['GET'])
@token_required
def get_all_note(current_user):
    notes= Notes.query.filter_by(owner=current_user)
    if not notes:
        return jsonify({"message":" not notes for this subject"})
    output=[]
    for noties in notes:
        note_data={}
        note_data['subject']=noties.subject
        note_data['notes']=noties.note
        output.append(note_data)
    return jsonify({"notes":output})

if __name__ == "__main__":
    app.run(debug=True)