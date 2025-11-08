from flask import Flask, render_template, request, jsonify
import joblib
import requests
import os
import pandas as pd

app = Flask(__name__)

# -------------------- Load ML model --------------------
model = joblib.load("model.pkl")

# -------------------- Extract features from URL --------------------
def extract_features(url):
    """Extract features that exactly match training data columns."""
    d = {
        'url_len': len(url),
        'dots': url.count('.'),
        'https': 1 if url.startswith('https') else 0,
        'has_at': 1 if '@' in url else 0,
        'digits': sum(c.isdigit() for c in url),
        'sus_word': 1 if any(s in url.lower() for s in ['login', 'secure', 'update', 'verify']) else 0
    }
    return pd.DataFrame([d])



# -------------------- VirusTotal submission --------------------
def check_virustotal(url):
    VT_API_KEY = os.environ.get("VT_API_KEY", "")
    if not VT_API_KEY:
        print("⚠️  VirusTotal API key not set in environment.")
        return {"error": "VirusTotal API key not configured"}

    headers = {"x-apikey": VT_API_KEY}
    vt_url = "https://www.virustotal.com/api/v3/urls"
    try:
        resp = requests.post(vt_url, headers=headers, data={"url": url})
        data = resp.json()
        analysis_id = data.get("data", {}).get("id")
        if not analysis_id:
            return {"error": "No analysis ID returned by VirusTotal"}
        return {"queued": True, "analysis_id": analysis_id}
    except Exception as e:
        print("Error submitting to VirusTotal:", e)
        return {"error": str(e)}

# -------------------- VirusTotal polling route --------------------
@app.route('/api/vt_status/<analysis_id>', methods=['GET'])
def vt_status(analysis_id):
    """Poll VirusTotal analysis status."""
    VT_API_KEY = os.environ.get("VT_API_KEY", "")
    if not VT_API_KEY:
        return jsonify({"error": "VirusTotal API key not configured"}), 400

    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        print("VirusTotal response:", resp.text[:200])  # debug
        data = resp.json()

        attr = data.get("data", {}).get("attributes", {})
        status = attr.get("status", "unknown")
        stats = attr.get("stats", {})
        results = attr.get("results", {})

        return jsonify({
            "status": status,
            "stats": stats,
            "vendors_checked": len(results)
        })
    except Exception as e:
        print("Error contacting VirusTotal:", e)
        return jsonify({"error": str(e)}), 500
    
    

# -------------------- Home route --------------------
@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    vt = None

    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            result = {"error": "Please enter a URL."}
        else:
            # --- Predict using ML model ---
            try:
                features = extract_features(url)
                prediction = model.predict(features)[0]
                label = "Phishing ⚠️" if prediction == 1 else "Legitimate ✅"
                result = {"label": label}
            except Exception as e:
                result = {"error": f"Prediction error: {str(e)}"}

            # --- Submit to VirusTotal ---
            
            vt = check_virustotal(url)

    return render_template('index.html', result=result, vt=vt)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')  # The dashboard file we created

@app.route('/check', methods=['POST'])
def check_url():
    url = request.form.get('url') or request.json.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    prediction = predict_url(url)  # your detection logic here
    vt = prediction.get("vt", {})

    result = {
        "url": url,
        "label": prediction.get("label"),
        "confidence": float(prediction.get("confidence") or 0),
        "vt_malicious": vt.get("malicious", 0),
        "vt_suspicious": vt.get("suspicious", 0),
        "vt_harmless": vt.get("harmless", 0),
        "vt_undetected": vt.get("undetected", 0)
    }

    payload = record_and_broadcast(result)
    return jsonify(payload), 200


# -------------------- Run the app --------------------
if __name__ == '__main__':
    # Make sure you set your VirusTotal API key before running:
    # set VT_API_KEY=your_api_key_here  (Windows)
    # export VT_API_KEY=your_api_key_here  (Mac/Linux)
    app.run(debug=True)

    if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

