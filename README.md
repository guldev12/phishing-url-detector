Phishing URL Detector (AI + Flask + VirusTotal)
==============================================

This is a simple, ready-to-run project that demonstrates a basic phishing URL detection web app.

Setup (Laptop/PC)
------------------
1. Clone or unzip the project folder.
2. Create a Python virtual environment and activate it:
   - python -m venv venv
   - venv\Scripts\activate   (Windows) or source venv/bin/activate (mac/linux)
3. Install requirements:
   - pip install -r requirements.txt
4. (Optional) If you want VirusTotal checks, set your VirusTotal API key in environment:
   - Windows (CMD): set VT_API_KEY=your_key_here
   - PowerShell: $env:VT_API_KEY="your_key_here"
   - mac/linux: export VT_API_KEY=your_key_here
5. Train the model (creates model/phishing_model.pkl):
   - python model_train.py
6. Run the Flask app:
   - python app.py
7. Open http://127.0.0.1:5000 in your browser.

Files
-----
- app.py               : Flask app (main)
- features.py          : Feature extraction used by app and trainer
- model_train.py       : Script to train and save the model using sample dataset
- model/phishing_model.pkl : (created after training)
- dataset/urls.csv     : Sample dataset (small). Replace with larger datasets for better results.
- templates/index.html : Frontend HTML
- static/style.css     : Simple styling
- requirements.txt     : Python dependencies
- README.md            : This file

Notes
-----
- The included dataset is intentionally small for demo purposes. For production-grade detection,
  use larger curated datasets and more advanced feature engineering / models.
- VirusTotal API calls can be rate-limited. Use responsibly.
- Do NOT hardcode API keys in code for production. Use environment variables or secret stores.
