import csv
from io import BytesIO
from flask import Flask, request, render_template, redirect, url_for, flash, session, send_file
from flask_cors import CORS
from flask_session import Session
from flask_wtf import CSRFProtect
import os
from dotenv import load_dotenv
import boto3
import secrets
import math
from urllib.parse import unquote
import json
from functools import wraps
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pandas as pd

load_dotenv()


app = Flask(__name__)
CORS(app)
csrf_token = CSRFProtect(app)

app.secret_key = os.getenv('SECRET_KEY') or secrets.token_urlsafe(64)

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_FILE_DIR'] = './browser_session/'
app.config['IAM_ROLE'] = os.getenv("IAM_ROLE")

Session(app)

ITEMS_PER_PAGE = 5

def init_db():
    with sqlite3.connect("s3_browser.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                permissions TEXT,
                permission_expiry DATE,  -- Date format: YYYY-MM-DD
                last_login TIMESTAMP,
                last_logout TIMESTAMP
            );
        """)
        conn.commit()

def check_permission_expiry(username):
    with sqlite3.connect("s3_browser.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT permission_expiry FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result and result[0]:  # result[0] is the permission_expiry date string
            permission_expiry_date = datetime.strptime(result[0], '%Y-%m-%d').date()
            return datetime.now().date() <= permission_expiry_date  # Returns True if not expired
        return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('username'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def get_s3_client():

    # credentials =assume_role('<role_arn>') # arn:aws:iam::account-id:role/role-name
    credentials = assume_role(app.config['IAM_ROLE'])
    
    aws_access_key_id = credentials.get('AccessKeyId')
    aws_secret_access_key = credentials.get('SecretAccessKey')
    aws_session_token = credentials.get('SessionToken')

    if not aws_access_key_id or not aws_secret_access_key:
        return None
    
    return boto3.client(
        's3',
        aws_access_key_id = aws_access_key_id,
        aws_secret_access_key = aws_secret_access_key,
        aws_session_token = aws_session_token,
        region_name = os.getenv('AWS_REGION', 'us-east-1')
    )

def assume_role(role_arn):
    sts_client = boto3.client('sts')
    response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName='AssumeRoleSession'
    )
    return response['Credentials']

@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/download_audit', methods=['GET'])
@login_required
@admin_required
def download_audit():
    with sqlite3.connect("s3_browser.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT username, permissions, permission_expiry, last_login, last_logout FROM users
        """)
        users = cursor.fetchall()

    # Convert data to a DataFrame
    df = pd.DataFrame(users, columns=['Username', 'Permissions', 'Permission Expiry', 'Last Login', 'Last Logout'])

    # Convert 'Last Login' and 'Last Logout' to readable format
    df['Last Login'] = pd.to_datetime(df['Last Login'], errors='coerce').dt.strftime('%Y-%m-%d %H:%M:%S')
    df['Last Logout'] = pd.to_datetime(df['Last Logout'], errors='coerce').dt.strftime('%Y-%m-%d %H:%M:%S')

    # Write the DataFrame to a BytesIO object (in-memory CSV)
    output = BytesIO()
    df.to_csv(output, index=False)

    # Seek to the beginning of the file-like object before sending
    output.seek(0)

    # Return the CSV file as an attachment
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name="user_audit.csv"
    )


def add_admin_user():
    with sqlite3.connect("s3_browser.db") as conn:
        cursor = conn.cursor()
        hashed_password = generate_password_hash("18Cb)mK8+JEo")  # Set your admin password here
        try:
            cursor.execute("INSERT INTO users (username, password, role, permissions) VALUES (?, ?, ?, ?)",
                           ("admin", hashed_password, "admin", ""))
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # Admin user already exists


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with sqlite3.connect("s3_browser.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password, role, permissions FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()

            if result and check_password_hash(result[0], password):
                # Update last_login timestamp
                cursor.execute("UPDATE users SET last_login = ? WHERE username = ?", 
                               (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username))
                conn.commit()

                session['username'] = username
                session['role'] = result[1]
                session['permissions'] = result[2].split(',')
                flash('Login successful.', 'success')
                return redirect(url_for('admin' if session['role'] == 'admin' else 'buckets'))
            else:
                flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    with sqlite3.connect("s3_browser.db") as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET last_logout = ? WHERE username = ?", 
                       (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), session['username']))
        conn.commit()

    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

    
@app.route('/admin', methods=['GET', 'POST'])
@login_required
@admin_required
def admin():
    if request.method == 'POST':
        # Handle user creation and permissions assignment
        username = request.form.get('username')
        password = request.form.get('password')
        bucket_names = request.form.get('bucket_names').split(',')
        permission_expiry = request.form.get('permission_expiry')  # Get expiration date

        hashed_password = generate_password_hash(password)

        with sqlite3.connect("s3_browser.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()

            if user:
                flash('User already exists.', 'danger')
            else:
                # Join the list of bucket names into a comma-separated string
                permissions = ",".join(bucket.strip() for bucket in bucket_names)
                cursor.execute("INSERT INTO users (username, password, role, permissions, permission_expiry) VALUES (?, ?, ?, ?, ?)",
                               (username, hashed_password, 'user', permissions, permission_expiry))
                conn.commit()
                flash('User created successfully.', 'success')
    
    elif request.method == 'GET' and 'username_view' in request.args:
        # Handle viewing permissions for a specific user
        username = request.args.get('username_view')
        with sqlite3.connect("s3_browser.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT permissions, permission_expiry FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()

            if result:
                permissions = result[0].split(',') if result[0] else []
                permission_expiry = result[1]  # Get expiration date
                user_permissions = {perm: permission_expiry for perm in permissions}
                return render_template('admin.html', user_permissions=user_permissions, current_user=username)
            else:
                flash('User not found.', 'danger')

    return render_template('admin.html')


# Remove a specific bucket permission
@app.route('/remove_permission', methods=['POST'])
@admin_required
def remove_permission():
    username = request.form['username']
    bucket_name = request.form['bucket_name']

    with sqlite3.connect("s3_browser.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT permissions FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            permissions = result[0].split(',')
            updated_permissions = [perm for perm in permissions if perm != bucket_name]
            cursor.execute("UPDATE users SET permissions = ? WHERE username = ?", (','.join(updated_permissions), username))
            conn.commit()
            flash('Permission removed successfully!', 'success')

    return redirect(url_for('admin', username_view=username))

# Remove all permissions for a user
@app.route('/remove_all_permissions', methods=['POST'])
@admin_required
def remove_all_permissions():
    username = request.form['username']

    with sqlite3.connect("s3_browser.db") as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET permissions = ? WHERE username = ?", ("", username))
        conn.commit()
        flash('All permissions removed successfully!', 'success')

    return redirect(url_for('admin', username_view=username))

@app.route('/add_permission', methods=['POST'])
@admin_required
def add_permission():
    username = request.form['username']
    new_bucket_name = request.form['new_bucket_name']

    with sqlite3.connect("s3_browser.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT permissions FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result:
            permissions = result[0].split(',') if result[0] else []
            if new_bucket_name not in permissions:
                permissions.append(new_bucket_name)
                cursor.execute("UPDATE users SET permissions = ? WHERE username = ?", (','.join(permissions), username))
                conn.commit()
                flash('Permission added successfully!', 'success')
            else:
                flash('User already has permission for this bucket.', 'warning')

    return redirect(url_for('admin', username_view=username))

# @app.route('/credentials', methods=['GET', 'POST'])
# def credentials():
#     if request.method == 'POST':
#         aws_access_key_id = request.form.get("aws_access_key_id")
#         aws_secret_access_key = request.form.get('aws_secret_access_key')
#         aws_session_token = request.form.get('aws_session_token')

#         if not aws_access_key_id or not aws_secret_access_key:
#             flash('Access Key ID and Secret Access Key are required.', 'danger')
#             return redirect(url_for('credentials'))
        
#         try:
#             client = boto3.client(
#                 's3',
#                 aws_access_key_id=aws_access_key_id,
#                 aws_secret_access_key=aws_secret_access_key,
#                 aws_session_token=aws_session_token,
#                 region_name=os.getenv('AWS_REGION', 'us-east-1')
#             )
#             client.list_buckets()
#         except Exception as e:
#             print(e)
#             flash('Invalid AWS credentials. Please try again.', 'danger')
#             return redirect(url_for('credentials'))
        
#         session['aws_access_key_id'] = aws_access_key_id
#         session['aws_secret_access_key'] = aws_secret_access_key
#         session['aws_session_token'] = aws_session_token

#         flash('AWS credentials set successfully.', 'success')
#         return redirect(url_for('buckets'))
    
#     return render_template('credentials.html')

@app.route('/clear_credentials')
def clear_credentials():
    session.pop('aws_access_key_id', None)
    session.pop('aws_secret_access_key', None)
    session.pop('aws_session_token', None)
    flash('AWS credentials cleared.', 'info')

    return redirect(url_for('credentials'))



@app.route('/buckets')
@login_required
def buckets():

    if not check_permission_expiry(session.get('username')):
        flash('Your permissions have expired. Please contact admin.', 'danger')
        return redirect(url_for('login'))
    
    client = get_s3_client()
    # if not client:
    #     flash('Please set your AWS credentials first.', 'warning')
    #     return redirect(url_for('credentials'))
    
    page = int(request.args.get('page', 1))
    search_term = request.args.get('search', '')

    try:
        response = client.list_buckets()
        all_buckets = response.get('Buckets', [])

        user_permissions = session.get('permissions', [])
        buckets = [bucket for bucket in all_buckets if bucket['Name'] in user_permissions]
        
        if search_term:
            buckets = [bucket for bucket in buckets if search_term.lower() in bucket['Name'].lower()]

        total_pages = math.ceil(len(buckets) / ITEMS_PER_PAGE)
        buckets = buckets[(page - 1) * ITEMS_PER_PAGE: page * ITEMS_PER_PAGE]

        return render_template('buckets.html', buckets=buckets, page=page, total_pages=total_pages, search_term=search_term)
    except Exception as e:
        print(e)
        flash('Error fetching buckets. Please check your credentials.', 'danger')
        return render_template('buckets.html', buckets=[])


@app.route('/buckets/<bucket_name>/objects')
def objects(bucket_name):
    client = get_s3_client()
    if not client:
        flash('Please set your AWS credentials first.', 'warning')
        return redirect(url_for('credentials'))
    
    page = int(request.args.get('page', 1))
    search_term = request.args.get('search', '')

    try:
        paginator = client.get_paginator('list_objects_v2')
        response_iterator = paginator.paginate(Bucket=bucket_name, Prefix=search_term)
        
        objects = []
        for response in response_iterator:
            objects.extend(response.get('Contents', []))
        
        total_pages = math.ceil(len(objects) / ITEMS_PER_PAGE)
        objects = objects[(page - 1) * ITEMS_PER_PAGE: page * ITEMS_PER_PAGE]

        return render_template('objects.html', bucket_name=bucket_name, objects=objects, page=page, total_pages=total_pages, search_term=search_term)
    except Exception as e:
        print(e)
        flash('Error fetching objects.', 'danger')
        return render_template('objects.html', bucket_name=bucket_name, objects=[])
    

@app.route('/buckets/<bucket_name>/download/<path:object_key>')
def download(bucket_name, object_key):
    client = get_s3_client()
    if not client:
        flash('Please set your AWS credentials first.', 'warning')
        return redirect(url_for('credentials'))
    
    try:
        # Decode object_key from URL encoding
        object_key = unquote(object_key)
        
        url = client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': bucket_name,
                'Key': object_key
            },
            ExpiresIn=60
        )
        return redirect(url)
    except Exception as e:
        print(e)
        flash('Error generating download link.', 'danger')
        return redirect(url_for('objects', bucket_name=bucket_name))

if __name__ == '__main__':
    init_db()
    add_admin_user()
    if not os.path.exists(app.config['SESSION_FILE_DIR']):
        os.mkdir(app.config['SESSION_FILE_DIR'])

    app.run(host='0.0.0.0', port=5000, debug=True)


# print(get_s3_client().list_buckets()['Buckets'])