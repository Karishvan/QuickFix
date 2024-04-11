from flask import Flask, request ,render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired
from models import db, User

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quickFix.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db.init_app(app)

sprints = []
bugs = {}
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
            
            authenticated = user.verify_password(password)
            if authenticated:
                # Successful login
                flash('Login successful!', 'success')
                # Redirect to a dashboard or profile page
                return redirect(url_for('dashboard'))
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
            new_user = User(username=username, email=email)
            #Use hashing method defined in models.py
            new_user.password = password
            print("adding to db")
            db.session.add(new_user)
            db.session.commit()
            message = "User created successfully!"
    return render_template('signup.html', form=form, message=message)



# sprint functions

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', sprints=sprints)

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
        sprints.append({'id': sprint_id, 'name': name})
        bugs[sprint_id] = []
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

if __name__ == '__main__':
    app.run(debug=True)
