# Flask User Authentication & Profile Management App

This is a simple Flask application that supports user authentication, profile management, and administrative features. It allows users to register, login, update their profiles, and manage their account settings (including changing their username, password, and profile picture). Administrators have the ability to manage users, including adding new users and deleting existing ones.

## Features
- User registration and login
- Profile management (change username, password, and profile picture)
- Admin dashboard to manage users (add, view, delete)
- Secure password hashing
- Flash messages for feedback
- Profile picture upload functionality

## Prerequisites
- Python 3.x
- Flask
- Flask-SQLAlchemy
- Werkzeug (for password hashing)
- SQLite (used as the default database)

## Installation

### Step 1: Clone the Repository
```bash
git clone https://github.com/yourusername/flask-user-profile-app.git
cd flask-user-profile-app


### Additional Notes:
1. **Requirements File**: Be sure to have a `requirements.txt` file with the dependencies listed, which should look like this:
   ```txt
   Flask==2.2.3
   Flask-SQLAlchemy==3.0.3
   Werkzeug==2.2.3
