from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_cors import CORS
from flask_session import Session
from flask_wtf import CSRFProtect
import os
from dotenv import load_dotenv
import boto3
import secrets
import math
from urllib.parse import unquote

load_dotenv()

app = Flask(__name__)
CORS(app)
csrf_token = CSRFProtect(app)

app.secret_key = os.getenv('SECRET_KEY') or secrets.token_urlsafe(64)

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_FILE_DIR'] = './browser_session/'

Session(app)

ITEMS_PER_PAGE = 5

def get_s3_client():
    
    aws_access_key_id = session.get('aws_access_key_id')
    aws_secret_access_key = session.get('aws_secret_access_key')
    aws_session_token = session.get('aws_session_token')

    if not aws_access_key_id or not aws_secret_access_key:
        return None
    
    return boto3.client(
        's3',
        aws_access_key_id = aws_access_key_id,
        aws_secret_access_key = aws_secret_access_key,
        aws_session_token = aws_session_token,
        region_name = os.getenv('AWS_REGION', 'us-east-1')
    )

@app.route('/')
def index():
    return redirect(url_for('credentials'))


@app.route('/credentials', methods=['GET', 'POST'])
def credentials():
    if request.method == 'POST':
        aws_access_key_id = request.form.get("aws_access_key_id")
        aws_secret_access_key = request.form.get('aws_secret_access_key')
        aws_session_token = request.form.get('aws_session_token')

        if not aws_access_key_id or not aws_secret_access_key:
            flash('Access Key ID and Secret Access Key are required.', 'danger')
            return redirect(url_for('credentials'))
        
        try:
            client = boto3.client(
                's3',
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
                region_name=os.getenv('AWS_REGION', 'us-east-1')
            )
            client.list_buckets()
        except Exception as e:
            print(e)
            flash('Invalid AWS credentials. Please try again.', 'danger')
            return redirect(url_for('credentials'))
        
        session['aws_access_key_id'] = aws_access_key_id
        session['aws_secret_access_key'] = aws_secret_access_key
        session['aws_session_token'] = aws_session_token

        flash('AWS credentials set successfully.', 'success')
        return redirect(url_for('buckets'))
    
    return render_template('credentials.html')

@app.route('/clear_credentials')
def clear_credentials():
    session.pop('aws_access_key_id', None)
    session.pop('aws_secret_access_key', None)
    session.pop('aws_session_token', None)
    flash('AWS credentials cleared.', 'info')

    return redirect(url_for('credentials'))



@app.route('/buckets')
def buckets():
    client = get_s3_client()
    if not client:
        flash('Please set your AWS credentials first.', 'warning')
        return redirect(url_for('credentials'))
    
    page = int(request.args.get('page', 1))
    search_term = request.args.get('search', '')

    try:
        response = client.list_buckets()
        buckets = response.get('Buckets', [])
        
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
    if not os.path.exists(app.config['SESSION_FILE_DIR']):
        os.mkdir(app.config['SESSION_FILE_DIR'])

    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=True)