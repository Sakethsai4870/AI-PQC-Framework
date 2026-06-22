from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class ScanResult(db.Model):
    __tablename__ = 'scan_results'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    ssl_version = db.Column(db.String(50))
    cipher_suite = db.Column(db.String(255))
    key_algorithm = db.Column(db.String(100))
    key_size = db.Column(db.Integer)
    cert_expiry = db.Column(db.String(50))
    quantum_risk_score = db.Column(db.Float)
    risk_level = db.Column(db.String(20))
    recommendations = db.Column(db.Text)
    headers_score = db.Column(db.Float)
    overall_score = db.Column(db.Float)
    raw_data = db.Column(db.Text)

    def to_dict(self):
        return {
            'id': self.id,
            'domain': self.domain,
            'scan_date': self.scan_date.isoformat() if self.scan_date else None,
            'ssl_version': self.ssl_version,
            'cipher_suite': self.cipher_suite,
            'key_algorithm': self.key_algorithm,
            'key_size': self.key_size,
            'cert_expiry': self.cert_expiry,
            'quantum_risk_score': self.quantum_risk_score,
            'risk_level': self.risk_level,
            'recommendations': self.recommendations,
            'headers_score': self.headers_score,
            'overall_score': self.overall_score,
        }
