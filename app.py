from flask import Flask, render_template, request, redirect, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure value

# MySQL Database Connection
db = mysql.connector.connect(
    host="localhost",
    user="root",         # 🔁 Replace with your MySQL username
    password="9044", # 🔁 Replace with your MySQL password
    database="user_system"
)
cursor = db.cursor()

# Utility to get client's real IP address
def get_client_ip():
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0]
    else:
        ip = request.remote_addr
    return ip

def get_location_from_ip(ip):
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        data = response.json()
        if 'error' in data:
            return "Unknown"
        city = data.get("city", "")
        region = data.get("region", "")
        country = data.get("country_name", "")
        return f"{city}, {region}, {country}".strip(", ")
    except:
        return "Unknown"

# Home route
@app.route('/')
def home():
    return redirect('/login')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm']

        ip = get_client_ip()
        location = get_location_from_ip(ip)

        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')

        if latitude and longitude and latitude != 'None' and longitude != 'None':
            precise_location = f"{latitude}, {longitude}"
        else:
            precise_location = "Unknown"

        now = datetime.now()

        if password != confirm_password:
            return "Passwords do not match."

        hashed = generate_password_hash(password)

        cursor.execute("""
            INSERT INTO users (username, email, password_hash, ip_address, registration_date, location, precise_location)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (username, email, hashed, ip, now, location, precise_location))
        db.commit()

        return redirect('/login')

    return render_template('register.html')



# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        ip = get_client_ip()
        location = get_location_from_ip(ip)

        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')

        if latitude and longitude and latitude != 'None' and longitude != 'None':
            precise_location = f"{latitude}, {longitude}"
        else:
            precise_location = "Unknown"

        now = datetime.now()

        # Fetch password hash and status of user
        cursor.execute("SELECT password_hash, status FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()

        if result:
            password_hash, user_status = result

            # 🚫 Blocked User Check
            if user_status.strip().lower().startswith('blocked'):
                return "🚫 Access Denied: Your account has been blocked by admin."


            if check_password_hash(password_hash, password):
                session['username'] = username
                session['is_admin'] = False

                cursor.execute("""
                    INSERT INTO login_attempts (username, ip_address, login_time, location, precise_location)
                    VALUES (%s, %s, %s, %s, %s)
                """, (username, ip, now, location, precise_location))
                db.commit()

                return redirect('/user-home')
            else:
                return "Incorrect password."
        else:
            return "User not found."

    return render_template('login.html')




@app.route('/dashboard')
def dashboard():
    if not session.get('username') or not session.get('is_admin'):
        return "Access Denied: Admins only"

    # Fetch Registered Users
    cursor.execute("""
        SELECT username, email, ip_address, registration_date, location, status, precise_location, country_from_gps
        FROM users
        ORDER BY registration_date DESC
    """)
    users = cursor.fetchall()

    # Fetch Login Attempts (excluding admin logins if needed)
    cursor.execute("""
        SELECT id, username, ip_address, login_time, location, precise_location, country_from_gps, status
        FROM login_attempts
        WHERE username != 'admin'
        ORDER BY login_time DESC
    """)
    logins = cursor.fetchall()

    return render_template('dashboard.html', users=users, logins=logins)

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip = get_client_ip()
        location = get_location_from_ip(ip)

        now = datetime.now()

        cursor.execute("SELECT password_hash, is_admin FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()

        if result and check_password_hash(result[0], password):
            if result[1] == 1:
                session['username'] = username
                session['is_admin'] = True

                cursor.execute("""INSERT INTO login_attempts (username, ip_address, login_time, location)VALUES (%s, %s, %s, %s)""", (username, ip, now, location))
                db.commit()

                return redirect('/dashboard')
            else:
                return "Access denied: You are not an admin."
        else:
            return "Invalid credentials"

    return render_template('admin_login.html')


# Logout (optional)
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

@app.route('/user-home')
def user_home():
    if 'username' not in session:
        return redirect('/login')
    return f"Welcome, {session['username']}! You are logged in as a normal user."

@app.route('/update-status', methods=['POST'])
def update_status():
    if not session.get('is_admin'):
        return "Access Denied"

    attempt_id = request.form['attempt_id']
    new_status = request.form['status']

    cursor.execute("""UPDATE login_attempts SET status = %s WHERE id = %s""", (new_status, attempt_id))
    db.commit()

    return redirect('/dashboard')

@app.route('/update-user-status', methods=['POST'])
def update_user_status():
    if not session.get('is_admin'):
        return "Access Denied"

    username = request.form['username']
    new_status = request.form['status']

    cursor.execute("""
        UPDATE users
        SET status = %s
        WHERE username = %s
    """, (new_status, username))
    db.commit()

    return redirect('/dashboard')

if __name__ == '__main__':
    app.run(debug=True)
