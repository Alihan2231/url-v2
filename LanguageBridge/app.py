import os
import json
import uuid
import logging
import datetime
from urllib.parse import urlparse
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase

# Set up logging
logging.basicConfig(level=logging.DEBUG)

# Base class for SQLAlchemy models
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "guvenlitarayici2024")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///url_scanner.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize database
db.init_app(app)

# Import models after db initialization
with app.app_context():
    from models import URLScan
    db.create_all()

# Google Safe Browsing API key and URL
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Function to check if a URL is in data/scan_history.json
def check_url_in_history(url):
    try:
        with open('data/scan_history.json', 'r') as f:
            history = json.load(f)
            
        for scan in history:
            if scan['url'] == url:
                # If the scan is less than 24 hours old, return it
                scan_time = datetime.datetime.fromisoformat(scan['timestamp'])
                now = datetime.datetime.now()
                if (now - scan_time).total_seconds() < 86400:  # 24 hours
                    return scan
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    
    return None

# Function to save scan result to history
def save_scan_to_history(scan_result):
    try:
        # Make sure data directory exists
        os.makedirs('data', exist_ok=True)
        
        # Try to load existing history
        try:
            with open('data/scan_history.json', 'r') as f:
                history = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            history = []
        
        # Add new scan to history
        history.append(scan_result)
        
        # Limit history to most recent 100 scans
        if len(history) > 100:
            history = history[-100:]
        
        # Save updated history
        with open('data/scan_history.json', 'w') as f:
            json.dump(history, f, indent=4, default=str)
            
    except Exception as e:
        app.logger.error(f"Error saving scan history: {str(e)}")

# Function to check URL safety using Google Safe Browsing API
def check_url_safety(url):
    try:
        # Get the already saved scan if it exists (less than 24h old)
        cached_scan = check_url_in_history(url)
        if cached_scan:
            app.logger.info(f"Using cached scan for {url}")
            return cached_scan
            
        # Parse the URL to ensure it's valid
        parsed_url = urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError("Geçersiz URL formatı")
        
        # Prepare the request to Google Safe Browsing API
        payload = {
            "client": {
                "clientId": "url-scanner-app",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", 
                    "SOCIAL_ENGINEERING", 
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        # Make the API call
        response = requests.post(
            SAFE_BROWSING_URL,
            params={"key": GOOGLE_API_KEY},
            json=payload
        )
        
        # Parse the response
        if response.status_code == 200:
            result = response.json()
            
            # Check if any threats were found
            is_safe = "matches" not in result
            threat_types = []
            
            if not is_safe:
                for match in result.get("matches", []):
                    threat_types.append(match.get("threatType"))
            
            # Create scan result dictionary
            scan_id = str(uuid.uuid4())
            timestamp = datetime.datetime.now().isoformat()
            
            scan_result = {
                "id": scan_id,
                "url": url,
                "is_safe": is_safe,
                "threat_types": threat_types,
                "timestamp": timestamp,
                "raw_result": result
            }
            
            # Save scan to history
            save_scan_to_history(scan_result)
            
            # Also save to database
            new_scan = URLScan(
                scan_id=scan_id,
                url=url,
                is_safe=is_safe,
                threat_types=json.dumps(threat_types),
                timestamp=datetime.datetime.now(),
                raw_result=json.dumps(result)
            )
            db.session.add(new_scan)
            db.session.commit()
            
            return scan_result
        else:
            app.logger.error(f"API error: {response.status_code} - {response.text}")
            raise Exception(f"API hatası: {response.status_code}")
            
    except requests.RequestException as e:
        app.logger.error(f"Request error: {str(e)}")
        raise Exception(f"İstek hatası: {str(e)}")
    except Exception as e:
        app.logger.error(f"Error checking URL safety: {str(e)}")
        raise Exception(f"URL güvenlik kontrolü hatası: {str(e)}")

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    # Get URL from either POST form data or GET parameters
    if request.method == 'POST':
        url = request.form.get('url', '')
    else:
        url = request.args.get('url', '')
    
    # Basic validation
    if not url:
        flash('Lütfen bir URL giriniz.', 'danger')
        return redirect(url_for('index'))
    
    # Add http:// prefix if not present
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        # Check URL safety
        scan_result = check_url_safety(url)
        return render_template('scan_result.html', result=scan_result)
    except Exception as e:
        app.logger.error(f"URL taraması hatası: {str(e)}")
        flash(f'Hata: {str(e)}', 'danger')
        return redirect(url_for('index'))

@app.route('/history')
def history():
    try:
        # Try to load scan history
        try:
            with open('data/scan_history.json', 'r') as f:
                history = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            history = []
        
        # Sort history by timestamp (newest first)
        history.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return render_template('history.html', history=history)
    except Exception as e:
        flash(f'Tarama geçmişi yüklenirken hata oluştu: {str(e)}', 'danger')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
