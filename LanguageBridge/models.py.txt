from app import db
import datetime

class URLScan(db.Model):
    """Model for URL scan results"""
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(36), unique=True, nullable=False)
    url = db.Column(db.String(2048), nullable=False)
    is_safe = db.Column(db.Boolean, nullable=False)
    threat_types = db.Column(db.Text, nullable=True)  # JSON string
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now)
    raw_result = db.Column(db.Text)  # JSON string of raw API response
    
    def __repr__(self):
        return f'<URLScan {self.url}>'
