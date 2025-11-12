# app.py
# Complete Flask app with registration, login, and private notes (CRUD).
# Comments below explain every step for a beginner.

from flask import Flask, render_template, request, redirect, session, flash, url_for
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

# --------------------
# App Initialization
# --------------------
app = Flask(__name__)
app.secret_key = "myverysecretkey"  # change this in production

#---------------- EMAIL CONFIGURATION ----------------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'   # Gmail SMTP server
app.config['MAIL_PORT'] = 587                 # Mail server port
app.config['MAIL_USE_TLS'] = True             # Use TLS encryption
app.config['MAIL_USERNAME'] = "munagapriyanka1402@gmail.com"  # Sender email
app.config['MAIL_PASSWORD'] = "ldga nesl nptd ffwp"     # App Password from Gmail
 
mail = Mail(app)  # Initialize Flask-Mail with app
 
# Token Serializer (used for generating secure reset password links)
s = URLSafeTimedSerializer(app.secret_key)
 
# Dummy Database (Dictionary for example only — no real DB)
users = {"munagapriyanka1402@gmail.com": {"password": "pinky@123"}}

# --------------------
# Database Connection Helper
# --------------------
def get_db_connection():
    """
    Create and return a new MySQL connection.
    Edit host/user/password/database if yours are different.
    """
    conn = mysql.connector.connect(
        host="localhost",
        user="root",       # change if your MySQL username is different
        password="root",       # enter MySQL password if you have one
        database="notes" # the DB created from the SQL script above
    )
    return conn

# --------------------
# Home (redirect)
# --------------------
@app.route('/')
def home():
    # If logged in -> show notes, else -> show login
    if 'user_id' in session:
        return redirect('/viewall')
    return redirect('/login')
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')



# --------------------
# Register Route
# --------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    # If POST -> process registration form
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        # Basic checks (non-empty)
        if not username or not email or not password:
            flash("Please fill all fields.", "danger")
            return redirect('/register')

        # Hash the password before saving
        hashed_pw = generate_password_hash(password)

        conn = get_db_connection()
        cur = conn.cursor()

        # Check if username already exists
        cur.execute("SELECT id FROM users WHERE username = %s", (username,))
        exists = cur.fetchone()
        if exists:
            # Close connection and inform user
            cur.close()
            conn.close()
            flash("Username already taken. Choose another.", "danger")
            return redirect('/register')

        # Insert new user into users table
        cur.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                    (username, email, hashed_pw))
        conn.commit()
        cur.close()
        conn.close()

        flash("Registration successful! You can now log in.", "success")
        return redirect('/login')

    # If GET -> show registration form
    return render_template('register.html')

# --------------------
# Login Route
# --------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If POST -> authenticate
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        # Basic check
        if not username or not password:
            flash("Please enter username and password.", "danger")
            return redirect('/login')

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        # Check whether user exists and password matches
        if user and check_password_hash(user['password'], password):
            # Save user id and username in session for future access control
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f"Welcome, {user['username']}!", "success")
            return redirect('/viewall')
        else:
            flash("Invalid username or password.", "danger")
            return redirect('/login')

    # If GET -> show login page
    return render_template('login.html')

# Forgot Password Page
@app.route('/forgot_password')
def forgot_password():
    return render_template("forgot_password.html")
 
 
# Sending Reset Password Email Link
@app.route('/send_reset_link', methods=['POST'])
def send_reset_link():
    email = request.form['email']  # Get entered email
    
    # If email is not present in dummy database
    if email not in users:
        flash("Email not registered!")
        return redirect('/forgot_password')
    
    # Create secure token containing user's email
    token = s.dumps(email, salt='password-reset-salt')
    
    # Generate reset link using token
    link = f"http://localhost:5000/reset_password/{token}"
    
    # Create email message
    msg = Message("Password Reset Request", 
                  sender="janicode249@gmail.com",
                  recipients=[email])
    msg.body = f"Click the link to reset your password: {link}"
    mail.send(msg)  # Send email
    
    flash("Reset link sent to your email!")
    return redirect('/')
 
 
# Reset Password Page (User clicks the link from email)
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Decode token to get user's email
        email = s.loads(token, salt='password-reset-salt', max_age=300)  
        # max_age=300 → link valid for 5 minutes
    except SignatureExpired:
        return "Link expired! Try again."
    
    # After form submission → Save new password
    if request.method == 'POST':
        new_password = request.form['password']
        users[email]["password"] = new_password  # Update password in dummy DB
        flash("Password reset successful! Please login.")
        return redirect('/')
    
    # Show Reset Password Form
    return render_template("reset_password.html")

# --------------------
# Logout Route
# --------------------
@app.route('/logout')
def logout():
    # Clear session data
    session.clear()
    flash("You have been logged out.", "info")
    return redirect('/login')

# --------------------
# Add Note (CREATE)
# --------------------
@app.route('/addnote', methods=['GET', 'POST'])
def addnote():
    # Ensure user is logged in
    if 'user_id' not in session:
        flash("Please login first.", "warning")
        return redirect('/login')

    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        user_id = session['user_id']

        if not title or not content:
            flash("Title and content cannot be empty.", "danger")
            return redirect('/addnote')

        conn = get_db_connection()
        cur = conn.cursor()
        # Save note with user_id to keep notes private
        cur.execute("INSERT INTO notes (title, content, user_id) VALUES (%s, %s, %s)",
                    (title, content, user_id))
        conn.commit()
        cur.close()
        conn.close()

        flash("Note added successfully.", "success")
        return redirect('/viewall')

    # GET -> show add note form
    return render_template('addnote.html')

# --------------------
# View All Notes (READ ALL for logged-in user)
# --------------------
@app.route('/viewall')
def viewall():
    # Ensure user logged in
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    # Fetch only notes that belong to this user
    cur.execute("SELECT id, title, content, created_at FROM notes WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
    notes = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('viewnotes.html', notes=notes)

# --------------------
# View Single Note (READ ONE) - restricted
# --------------------
@app.route('/viewnotes/<int:note_id>')
def viewnotes(note_id):
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    # Select note only if it belongs to current user
    cur.execute("SELECT id, title, content, created_at FROM notes WHERE id = %s AND user_id = %s", (note_id, user_id))
    note = cur.fetchone()
    cur.close()
    conn.close()

    if not note:
        # Either note doesn't exist or doesn't belong to the user
        flash("You don't have access to this note.", "danger")
        return redirect('/viewall')

    return render_template('singlenote.html', note=note)

# --------------------
# Update Note (UPDATE) - restricted
# --------------------
@app.route('/updatenote/<int:note_id>', methods=['GET', 'POST'])
def updatenote(note_id):
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    # Check existence and ownership
    cur.execute("SELECT id, title, content FROM notes WHERE id = %s AND user_id = %s", (note_id, user_id))
    note = cur.fetchone()

    if not note:
        cur.close()
        conn.close()
        flash("You are not authorized to edit this note.", "danger")
        return redirect('/viewall')

    if request.method == 'POST':
        # Get updated data
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        if not title or not content:
            flash("Title and content cannot be empty.", "danger")
            return redirect(url_for('updatenote', note_id=note_id))

        # Update query guarded by user_id
        cur.execute("UPDATE notes SET title = %s, content = %s WHERE id = %s AND user_id = %s",
                    (title, content, note_id, user_id))
        conn.commit()
        cur.close()
        conn.close()
        flash("Note updated successfully.", "success")
        return redirect('/viewall')

    # If GET -> render update form with existing note data
    cur.close()
    conn.close()
    return render_template('updatenote.html', note=note)

# --------------------
# Delete Note (DELETE) - restricted
# --------------------
@app.route('/deletenote/<int:note_id>', methods=['POST'])
def deletenote(note_id):
    # This route expects a POST request (safer than GET for delete)
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor()
    # Delete only if the note belongs to the current user
    cur.execute("DELETE FROM notes WHERE id = %s AND user_id = %s", (note_id, user_id))
    conn.commit()
    cur.close()
    conn.close()
    flash("Note deleted.", "info")
    return redirect('/viewall')

# --------------------
# Run App
# --------------------
if __name__ == '__main__':
    # debug=True for development only
    app.run(debug=True)