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
# 🧠 ASLI DIMAAG: SCANNER FUNCTION
# ==========================================
def scan_vpn_config(config_text):
    score = 100
    findings = []
    fixes = []
    
    # Text ko lowercase me badal lo taaki search aasan ho
    text = config_text.lower()
    
    # Rule 1: Weak encryption (DES)
    if 'des' in text and '3des' not in text:
        score -= 30
        findings.append("Danger: Weak Encryption (DES) found.")
        fixes.append("Upgrade encryption to AES-256 or higher.")
        
    # Rule 2: Weak hashing (MD5)
    if 'md5' in text:
        score -= 25
        findings.append("Warning: Weak Hashing Algorithm (MD5) used.")
        fixes.append("Change hashing algorithm to SHA-256 or SHA-384.")
        
    # Rule 3: Weak Diffie-Hellman group
    if 'group 2' in text or 'group 1 ' in text:
        score -= 20
        findings.append("Warning: Weak Diffie-Hellman Group detected.")
        fixes.append("Use Diffie-Hellman Group 14 or higher for better security.")
        
    if score < 0:
        score = 0
        
    if score == 100:
        findings.append("Success: No obvious vulnerabilities found!")
        fixes.append("Keep your configurations up to date.")
        
    return score, findings, fixes

# ==========================================
# 🌐 ROUTES & ERROR HANDLING (FRONTEND CONNECTION)
# ==========================================
@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        uploaded_file = request.files['configFile']
        
        if uploaded_file.filename != '':
            try:
                # 1. File ko safely padhne ki koshish karo
                file_content = uploaded_file.read().decode('utf-8')
                
                # 2. Asli Scanner function ko call karo
                real_score, real_findings, real_fixes = scan_vpn_config(file_content)
                
                # 3. Database me real score save karo
                new_scan = ScanHistory(filename=uploaded_file.filename, score=real_score)
                db.session.add(new_scan)
                db.session.commit()
                
                # 4. Result UI par bhejo
                return render_template('index.html', 
                                       result_ready=True, 
                                       score=real_score, 
                                       findings_list=real_findings, 
                                       fixes_list=real_fixes)
                                       
            except UnicodeDecodeError:
                # 5. Agar user galat/corrupt file dale toh server crash hone se bachao
                error_findings = ["Error: Invalid file format or encoding detected."]
                error_fixes = ["Please upload a clean, plain text file (.txt or .conf) encoded in UTF-8."]
                
                return render_template('index.html', 
                                       result_ready=True, 
                                       score=0, 
                                       findings_list=error_findings, 
                                       fixes_list=error_fixes)

    # Jab user pehli baar website par aaye
    return render_template('index.html', result_ready=False)

if __name__ == '__main__':
    app.run(debug=True)