from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import re

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail configuration (update with your SMTP server details)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

from models import User  # Import the User model

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validate passwords
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('signup'))

        if not re.search(r'[!@#$%^&*]', password):
            flash("Password must include at least one special character (!@#$%^&*).", "danger")
            return redirect(url_for('signup'))

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Create and save the user
        try:
            user = User(username=username, email=email, password=hashed_password)
            db.session.add(user)
            db.session.commit()

            # Send a confirmation email
            send_confirmation_email(email)

            flash("Account created successfully! Please confirm your email.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash("Error creating account. Please try again later.", "danger")

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Validate user
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            flash("Logged in successfully!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password!", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return "Welcome to the Dashboard!"

def send_confirmation_email(email):
    try:
        msg = Message("Confirm Your Email", sender="your_email@gmail.com", recipients=[email])
        msg.body = "Thank you for signing up! Please confirm your email to activate your account."
        mail.send(msg)
    except Exception as e:
        print("Error sending email:", e)

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
