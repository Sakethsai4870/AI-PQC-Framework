import json
import urllib.parse
from flask import Flask, render_template, request, jsonify, send_file, abort
from config import Config
from database.database import db, ScanResult
from scanner.ssl_scanner import scan_ssl
from scanner.domain_scanner import scan_domain
from scanner.header_scanner import scan_headers
from scanner.feature_extractor import extract_features
from pqc.recommendation import generate_recommendations
from pqc.quantum import assess_quantum_risk
from ai.predictor import predict_risk, calculate_overall_score
from ai.explain import explain_prediction
from reports.pdf_generator import generate_pdf_report
from datetime import datetime
import requests as req

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

with app.app_context():
    db.create_all()


def clean_domain(domain):
    domain = domain.strip().lower()
    if domain.startswith('http://') or domain.startswith('https://'):
        parsed = urllib.parse.urlparse(domain)
        domain = parsed.netloc or parsed.path
    domain = domain.split('/')[0].split('?')[0].split('#')[0]
    return domain


@app.route('/')
def index():
    recent_scans = ScanResult.query.order_by(ScanResult.scan_date.desc()).limit(10).all()
    return render_template('index.html', recent_scans=recent_scans)


@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    if not data or not data.get('domain'):
        return jsonify({'error': 'Domain is required'}), 400

    domain = clean_domain(data['domain'])
    if not domain:
        return jsonify({'error': 'Invalid domain'}), 400

    try:
        ssl_data = scan_ssl(domain)
        domain_data = scan_domain(domain)
        header_data = scan_headers(domain)
        features = extract_features(ssl_data, domain_data, header_data)
        prediction = predict_risk(features)
        explanation = explain_prediction(features, prediction)
        recommendations = generate_recommendations(ssl_data, domain_data, header_data, features)
        overall_score = calculate_overall_score(prediction['score'], header_data.get('score', 0))

        rec_text = json.dumps({
            'priority_actions': recommendations['priority_actions'],
            'recommendations': recommendations['recommendations'][:5],
        })

        scan_result = ScanResult(
            domain=domain,
            ssl_version=ssl_data.get('ssl_version'),
            cipher_suite=ssl_data.get('cipher_suite'),
            key_algorithm=ssl_data.get('key_algorithm'),
            key_size=ssl_data.get('key_size'),
            cert_expiry=ssl_data.get('cert_expiry'),
            quantum_risk_score=prediction['score'],
            risk_level=prediction['risk_level'],
            recommendations=rec_text,
            headers_score=header_data.get('score', 0),
            overall_score=overall_score,
            raw_data=json.dumps({
                'ssl': ssl_data,
                'domain': domain_data,
                'headers': header_data,
            }),
        )
        db.session.add(scan_result)
        db.session.commit()

        return jsonify({
            'success': True,
            'scan_id': scan_result.id,
            'domain': domain,
            'ssl': ssl_data,
            'domain_info': domain_data,
            'headers': header_data,
            'features': features,
            'prediction': prediction,
            'explanation': explanation,
            'recommendations': recommendations,
            'overall_score': overall_score,
            'scan_date': scan_result.scan_date.isoformat(),
        })

    except Exception as e:
        return jsonify({'error': f'Scan failed: {str(e)}'}), 500


@app.route('/report/<int:scan_id>')
def view_report(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    raw = {}
    explanation = {}
    recommendations = {}
    try:
        raw = json.loads(scan.raw_data) if scan.raw_data else {}
        rec_data = json.loads(scan.recommendations) if scan.recommendations else {}
        recommendations = rec_data
    except Exception:
        pass

    return render_template('report.html', scan=scan, raw=raw, recommendations=recommendations)


@app.route('/report/<int:scan_id>/pdf')
def download_pdf(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    raw = {}
    recommendations = {}
    explanation = {}
    try:
        raw = json.loads(scan.raw_data) if scan.raw_data else {}
        rec_data = json.loads(scan.recommendations) if scan.recommendations else {}
        recommendations = rec_data
    except Exception:
        pass

    features = extract_features(
        raw.get('ssl', {}),
        raw.get('domain', {}),
        raw.get('headers', {}),
    )
    prediction = predict_risk(features)
    explanation = explain_prediction(features, prediction)

    pdf_data = {
        'domain': scan.domain,
        'scan_date': scan.scan_date.strftime('%Y-%m-%d %H:%M UTC') if scan.scan_date else '',
        'risk_level': scan.risk_level,
        'overall_score': scan.overall_score or 0,
        'ssl': raw.get('ssl', {}),
        'domain_info': raw.get('domain', {}),
        'headers': raw.get('headers', {}),
        'explanation': explanation,
        'recommendations': recommendations,
    }

    pdf_buffer = generate_pdf_report(pdf_data)
    return send_file(
        pdf_buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'pqc-report-{scan.domain}-{scan_id}.pdf',
    )


@app.route('/history')
def history():
    scans = ScanResult.query.order_by(ScanResult.scan_date.desc()).all()
    return render_template('history.html', scans=scans)


@app.route('/api/scans', methods=['GET'])
def api_scans():
    scans = ScanResult.query.order_by(ScanResult.scan_date.desc()).limit(50).all()
    return jsonify([s.to_dict() for s in scans])


@app.route('/api/scan/<int:scan_id>', methods=['GET'])
def api_scan(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    return jsonify(scan.to_dict())


if __name__ == '__main__':
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
