from flask import Flask

app = Flask(__name__)

# Yeh function batata hai ki jab koi main link (/) par jayega toh kya dikhega
@app.route('/')
def home():
    return "Hello Ajinkya! Welcome to IPsecGuard."

if __name__ == '__main__':
    # debug=True ka matlab hai ki jab hum code change karenge, website khud refresh ho jayegi
    app.run(debug=True)
    
    