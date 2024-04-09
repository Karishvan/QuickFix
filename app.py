from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quickFix.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db.init_app(app)

# Define SignupForm using Flask-WTF
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

with app.app_context():
    db.create_all()

@app.route('/')
def hello_world():
    return 'Hello, World!'

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        # Query the user from the database by username
        user = User.query.filter_by(username=username).first()
        if user:
            # Check if the password matches the hashed password in the database
            if user.password == password:
                # Successful login
                flash('Login successful!', 'success')
                # Redirect to a dashboard or profile page
                return redirect(url_for('index'))
            else:
                flash('Invalid username or password.', 'error')
        else:
            flash('Invalid username or password.', 'error')
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    message = None
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        # Check if the username or email already exists in the database
        existing_username = User.query.filter_by(username=username).first()
        existing_email = User.query.filter_by(email=email).first()
        if existing_username:
            message = f"Username '{username}' already exists."
        elif existing_email:
            message = f"Email '{email}' is already registered."
        else:
            # Create a new User object and add it to the database
            new_user = User(username=username, email=email, password=password)
            db.session.add(new_user)
            db.session.commit()
            message = "User created successfully!"
    return render_template('signup.html', form=form, message=message)

if __name__ == '__main__':
    app.run(debug=True)
