from flask import Flask, request ,render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, InputRequired, EqualTo
from models import db, User
from flask_migrate import Migrate
from flask_mail import Mail, Message
from flask_login import current_user, login_required, LoginManager, login_user, logout_user
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from io import BytesIO
import base64

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quickFix.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  
app.config['MAIL_PORT'] = 587  
app.config['MAIL_USE_TLS'] = True  # Enable TLS encryption
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USERNAME')  # Email username
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_APPPASS')  # App password

db.init_app(app)
login_manager = LoginManager(app)
# migrate = Migrate(app, db)

sprints = []
bugs = {}
graph = ''
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

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[InputRequired()])
    new_password = PasswordField('New Password', validators=[InputRequired(), EqualTo('confirm_password', message='Passwords must match')])
    confirm_password = PasswordField('Confirm New Password', validators=[InputRequired()])
    submit = SubmitField('Change Password')

with app.app_context():
    db.create_all()

@app.route('/logout')
def logout():
    logout_user()
    session.pop('_flashes', None)
    flash('Logout successful!', 'success')

    return redirect(url_for('login'))

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
            
            authenticated = user.verify_password(password)
            if authenticated:
                # Successful login

                # Redirect to a dashboard or profile page
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                session.pop('_flashes', None)
                flash('Invalid username or password.', 'error')
        else:
            session.pop('_flashes', None)
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
            new_user = User(username=username, email=email)
            #Use hashing method defined in models.py
            new_user.password = password
            db.session.add(new_user)
            db.session.commit()
            message = "User created successfully!"
    return render_template('signup.html', form=form, message=message)

mail = Mail(app)

# Add this new route for password reset
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate a temporary password and send it to the user's email
            temporary_password = generate_temporary_password()
            user.password = temporary_password
            db.session.commit()
            send_password_reset_email(email, temporary_password)
            session.pop('_flashes', None)
            flash('A temporary password has been sent to your email.', 'success')
            return redirect(url_for('login'))
        else:
            session.pop('_flashes', None)
            flash('No user found with that email address.', 'error')
            return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

# Helper function to generate a temporary password
def generate_temporary_password():
    import secrets
    import string
    temporary_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))
    return temporary_password

# Helper function to send password reset email
def send_password_reset_email(email, temporary_password):
    msg = Message('Password Reset', sender='quickfixnoreply@gmail.com', recipients=[email])
    msg.body = f'Your temporary password is: {temporary_password}. Please use this to login and reset your password.'
    mail.send(msg)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        # Check if the current password provided matches the user's actual password
        if current_user.verify_password(form.current_password.data):
            # Update the user's password with the new one
            current_user.password = form.new_password.data
            db.session.commit()
            session.pop('_flashes', None)
            flash('Password changed successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            session.pop('_flashes', None)
            flash('Incorrect current password.', 'error')
    return render_template('change_password.html', form=form)
@login_manager.user_loader
def load_user(user_id):
    # This function retrieves a user by their ID from the database
    return User.query.get(int(user_id))

@app.route('/view_graph', methods=['GET', 'POST'])
def view_graph():
    global graph
    if request.method == 'POST':
        # To do: get accurate data
        data = [7, 4, 5, 6]
        labels = ['Functional', 'Security', 'Compatibility', 'Other']

        #Generate graph
        plt.bar(labels, data)
        plt.xlabel('Types of Bugs')
        plt.ylabel('# of Bugs')
        plt.title('Bugs of Each Type')

        #Convert into readable format
        buffer = BytesIO()
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        image_png = buffer.read()
        buffer.close()
        graph = base64.b64encode(image_png).decode()

        #Redirect to dashboard route
        return redirect(url_for('dashboard'))

    return redirect(url_for('dashboard'))

#sprint functions
@app.route('/dashboard')

def dashboard():
    global graph
    sprint_bug_counts = {sprint['id']: len(bugs.get(sprint['id'], [])) for sprint in sprints}
    return render_template('dashboard.html', sprints=sprints, sprint_bug_counts=sprint_bug_counts)


@app.route('/sprint/<int:sprint_id>')
def bug_page(sprint_id):
    sprint = next((sprint for sprint in sprints if sprint['id'] == sprint_id), None)
    sprint_name = sprint['name'] if sprint else 'Unknown Sprint'
    sprint_bugs = bugs.get(sprint_id, [])
    return render_template('sprint.html', sprint_name=sprint_name, bugs=sprint_bugs, sprint_id=sprint_id)

@app.route('/create_sprint', methods=['POST'])
def create_sprint():
    name = request.form.get('name')
    if name:
        sprint_id = len(sprints) + 1
        author = current_user.username
        sprints.append({'id': sprint_id, 'name': name, 'author': author}) 
    return redirect('/dashboard')

@app.route('/delete_sprint/<int:sprint_id>', methods=['POST'])
def delete_sprint(sprint_id):
    global sprints
    sprints = [sprint for sprint in sprints if sprint['id'] != sprint_id]
    return redirect('/dashboard')

@app.route('/sprint/<int:sprint_id>/create_bug', methods=['POST'])
def create_bug(sprint_id):
    title = request.form.get('title')
    bug_type = request.form.get('bug_type')
    description = request.form.get('description')
    email_notification = request.form.get('email_notification')

    if title and description:
        bugs_list = bugs.get(sprint_id, [])
        bugs_list.append({
            'title': title,
            'type': bug_type,
            'description': description,
            'email_notification': email_notification == 'on'
        })
        bugs[sprint_id] = bugs_list

    return redirect(f'/sprint/{sprint_id}')

@app.route('/')
def landing():
    return render_template('homePage.html')

if __name__ == '__main__':
    app.run(debug=True)
