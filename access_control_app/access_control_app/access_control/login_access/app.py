from flask import Flask, render_template, request, redirect, url_for, session
from flask import request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename

# Directory to save uploaded profile pictures
UPLOAD_FOLDER = 'static/profile_pics'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/img/profile_pics'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# Ensure the directory exists
upload_folder = app.config['UPLOAD_FOLDER']
if not os.path.exists(upload_folder):
    os.makedirs(upload_folder)

db = SQLAlchemy(app)


# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    profile_picture = db.Column(db.String(150), default='default.jpg')

def __repr__(self):
        return f"<User {self.username}>"
# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash("Invalid credentials!")  # Use flash here for error messages
            return redirect(url_for('login'))  # Redirect after POST to avoid resubmitting form
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        return "Access denied!", 403
    
    users = User.query.all()

    # Check if the 'deleted_user' message exists in session and pass it to the template
    deleted_user_message = session.pop('deleted_user', None)

    return render_template('admin_dashboard.html', users=users, deleted_user_message=deleted_user_message)


@app.route('/user_dashboard', methods=['GET', 'POST'])
def user_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    
    if user is None:
        flash("User not found.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Update username
        username = request.form['username']
        user.username = username
        
        # Update password if provided
        password = request.form['password']
        if password:
            confirm_password = request.form['confirm_password']
            if password != confirm_password:
                flash("Passwords do not match!")
                return redirect(url_for('user_dashboard'))
            user.password = generate_password_hash(password, method='pbkdf2:sha256')

        # Handle profile picture upload
        if 'profile_pic' in request.files:
            profile_pic = request.files['profile_pic']
            if profile_pic and allowed_file(profile_pic.filename):
                filename = secure_filename(profile_pic.filename)
                profile_pic.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                user.profile_pic = filename  # Update the user's profile picture
                
        db.session.commit()
        flash("Profile updated successfully!")
        return redirect(url_for('user_dashboard'))
    
    return render_template('user_dashboard.html', user=user)


@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if not session.get('is_admin'):
        return "Access denied!", 403
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = 'is_admin' in request.form
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, is_admin=is_admin)
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('admin_dashboard'))
        except:
            return render_template('admin_register.html', error="Username already exists!")
    return render_template('admin_register.html')

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('is_admin'):
        return "Access denied!", 403
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        session['deleted_user'] = f"User {user.username} has been deleted."
    return redirect(url_for('admin_dashboard'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        is_admin = 'is_admin' in request.form

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match!")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, is_admin=is_admin)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Registration successful! Please login.")
            return redirect(url_for('login'))
        except:
            flash("Username already exists!")
            return redirect(url_for('register'))
    return render_template('register.html')

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        # Update username
        username = request.form['username']
        # Update password
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        # Handle profile picture upload
        file = request.files.get('profile_pic')

        # Check if password fields match
        if password != confirm_password:
            flash("Passwords do not match!")
            return redirect(url_for('edit_profile'))

        # If a new file is uploaded, save it
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)

            # Ensure the folder exists before saving
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)

            file.save(os.path.join(upload_folder, filename))  # Save the file
            user.profile_pic = filename  # Update the profile_pic field in the database

        # If password is provided, update it
        if password:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            user.password = hashed_password

        # Update the username if changed
        if username:
            user.username = username

        try:
            db.session.commit()
            flash("Profile updated successfully!")
            return redirect(url_for('user_dashboard'))  # Redirect to the user dashboard
        except:
            flash("There was an error updating the profile!")
            return redirect(url_for('edit_profile'))

    return render_template('edit_profile.html', user=user)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file uploaded', 400

    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400

    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        return f"File uploaded to {file_path}", 200

# Initialize database
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)