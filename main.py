from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app=Flask(__name__)

#db config
app.config['MYSQL_HOST']='localhost'
app.config['MYSQL_USER']='root'
app.config['MYSQL_PASSWORD']='12345'
app.config['MYSQL_DB']='FLASK'
app.config['MYSQL_CURSORCLASS']='DictCursor'
#init MySQL
mysql=MySQL(app)

#home
@app.route("/")
def home():
    return render_template('home.html')

#login
@app.route("/login",methods=['GET','POST'])
def login():
    if request.method=='POST':
        username=request.form['username']
        password_candidate=request.form['password']

        cur=mysql.connection.cursor()

        result=cur.execute("SELECT * FROM users WHERE username = %s",[username])

        if result>0:
            data=cur.fetchone()
            password=data['password']

            #compare
            if sha256_crypt.verify(password_candidate, password):
                #pass
                session['logged_in']=True
                session['username']=username

                flash('You are now logged in','success')
                return redirect(url_for('dashboard'))
            else:
                error='Invalid Login'
                return render_template('login.html',error=error)
            cur.close()
        else:
            error='Username Not Found'
            return render_template('login.html',error=error)


    return render_template('login.html')

#register form class
class RegisterForm(Form):
    name = StringField('Name',[validators.Length(min=1 , max=50)])
    username = StringField('Username',[validators.Length(min=4,max=25)])
    email = StringField('Email',[validators.Length(min=5,max=50)])
    password = PasswordField('Password',[
    validators.DataRequired(),
    validators.EqualTo('confirm', message='Passwords donot match')
    ])
    confirm = PasswordField('Confirm Password')


#check login status
#wraps a authorization for defined routes
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Pease login', 'danger')
            return redirect(url_for('login'))
    return wrap


#dashboard
@app.route('/dash')
@is_logged_in
def dashboard():
    return render_template('dashboard.html')


#Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out!')
    return redirect(url_for('home'))

#user registration
@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        #creating cursor
        cur=mysql.connection.cursor()
        cur.execute("insert into users (name, email, username, password) values (%s, %s, %s, %s) ", (name, email, username, password))
        #commit changes
        mysql.connection.commit()
        cur.close()

        flash('Successfully Registered, Please login','success')

        return redirect(url_for('login'))

        return render_template('register.html')
    return render_template('register.html',form=form)


if __name__=="__main__":
    app.secret_key='secret123'
    app.run(debug=True)
