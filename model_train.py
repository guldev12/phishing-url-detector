import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

BASE = os.path.dirname(__file__)
ds_path = os.path.join(BASE, 'dataset', 'urls.csv')
model_dir = os.path.join(BASE, 'model')
os.makedirs(model_dir, exist_ok=True)
model_path = os.path.join(model_dir, 'phishing_model.pkl')

df = pd.read_csv(ds_path)
df['url'] = df['url'].astype(str)
df['url_len'] = df['url'].apply(len)
df['dots'] = df['url'].apply(lambda x: x.count('.'))
df['https'] = df['url'].apply(lambda x: 1 if x.startswith('https') else 0)
df['has_at'] = df['url'].apply(lambda x: 1 if '@' in x else 0)
df['digits'] = df['url'].apply(lambda x: sum(c.isdigit() for c in x))
suspicious = ['login','secure','update','verify','bank','confirm','account','free','webscr','signin']
df['sus_word'] = df['url'].apply(lambda x: 1 if any(s in x for s in suspicious) else 0)

X = df[['url_len','dots','https','has_at','digits','sus_word']]
y = df['label'].map({'safe':0,'phishing':1})

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)
joblib.dump(model, model_path)
print("Model trained and saved at:", model_path)
