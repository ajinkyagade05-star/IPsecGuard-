from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)

# ==========================================
# 🗄️ DATABASE CONFIGURATION
# ==========================================
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ipsecguard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    date_scanned = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

# ==========================================
# 🧠 SCANNER FUNCTION (Enhanced for SIH Judges)
# ==========================================
def scan_vpn_config(config_text):
    score = 100
    findings = []
    fixes = []
    attack_stories = []
    compliance_tags = []
    
    text = config_text.lower()
    
    # Rule 1: Weak encryption (DES)
    if 'des' in text and '3des' not in text:
        score -= 30
        findings.append("Danger: Weak Encryption (DES) found.")
        fixes.append("set crypto ipsec transform-set TRANS-SET esp-aes-256 esp-sha-hmac")
        attack_stories.append("Critical Risk: DES uses a small 56-bit key, allowing attackers to brute-force encryption via GPU clusters.")
        compliance_tags.append("Violates NIST SP 800-77")
        
    # Rule 2: Weak hashing (MD5)
    if 'md5' in text:
        score -= 25
        findings.append("Warning: Weak Hashing Algorithm (MD5) used.")
        fixes.append("set crypto ipsec transform-set TRANS-SET esp-aes-256 esp-sha256-hmac")
        attack_stories.append("High Risk: MD5 collision vulnerabilities enable Man-in-the-Middle packet spoofing.")
        compliance_tags.append("Violates FIPS 140-2")
        
    # Rule 3: Weak Diffie-Hellman group
    if 'group 2' in text or 'group 1 ' in text:
        score -= 20
        findings.append("Warning: Weak Diffie-Hellman Group detected.")
        fixes.append("crypto isakmp policy 1\ngroup 14")
        attack_stories.append("Moderate Risk: DH Group 1/2 provide insufficient key exchange entropy.")
        compliance_tags.append("Violates NIST SP 800-56A")

    # --- NEW SIH WINNING RULES ADDED BELOW ---
    
    # Rule 4: Aggressive Mode vulnerability (IKEv1)
    if 'aggressive' in text:
        score -= 25
        findings.append("Danger: IKEv1 Aggressive Mode enabled.")
        fixes.append("crypto isakmp policy 1\n ! Use Main Mode instead of Aggressive Mode")
        attack_stories.append("Critical Risk: Aggressive mode transmits PSK hashes in cleartext, enabling offline dictionary attacks.")
        compliance_tags.append("Violates CIS Benchmark")

    # Rule 5: Overly Permissive Access List (Any-to-Any)
    if 'permit ip any any' in text or 'permit any any' in text:
        score -= 30
        findings.append("Danger: Overly Permissive ACL mapped to VPN.")
        fixes.append("access-list 100 permit ip [LOCAL_SUBNET] [MASK] [REMOTE_SUBNET] [MASK]")
        attack_stories.append("High Risk: Defeats Zero-Trust. Allows complete internal network traversal if the VPN tunnel is compromised.")
        compliance_tags.append("Violates Zero-Trust Architecture")
        
    if score < 0:
        score = 0
        
    if score == 100:
        findings.append("Success: No obvious vulnerabilities found!")
        fixes.append("# Configuration meets baseline standards.")
        attack_stories.append("Secure Posture: No active vectors exposed.")
        compliance_tags.append("Fully Compliant")
        
    return score, findings, fixes, attack_stories, compliance_tags

# ==========================================
# 🌐 ROUTES (Updated for Dual-Page Architecture)
# ==========================================
@app.route('/')
def home_page():
    return render_template('home.html')

@app.route('/analyzer', methods=['GET', 'POST'])
def analyzer():
    if request.method == 'POST':
        uploaded_files = request.files.getlist('configFile')
        batch_results = []
        
        for uploaded_file in uploaded_files:
            if uploaded_file and uploaded_file.filename != '':
                try:
                    file_content = uploaded_file.read().decode('utf-8')
                    score, findings, fixes, stories, compliance = scan_vpn_config(file_content)
                    
                    new_scan = ScanHistory(filename=uploaded_file.filename, score=score)
                    db.session.add(new_scan)
                    
                    batch_results.append({
                        'filename': uploaded_file.filename,
                        'score': score,
                        'findings': findings,
                        'fixes': fixes,
                        'stories': stories,
                        'compliance': compliance
                    })
                except Exception:
                    continue
                    
        db.session.commit()
        
        avg_score = 0
        if len(batch_results) > 0:
            total = sum(scan['score'] for scan in batch_results)
            avg_score = total // len(batch_results)
            
        return render_template('index.html', result_ready=True, batch_results=batch_results, avg_score=avg_score)

    return render_template('index.html', result_ready=False)

if __name__ == '__main__':
    print("🚀 Starting IPsecGuard Server by Byte Crews...")
    print("👉 Open this link in browser: http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)