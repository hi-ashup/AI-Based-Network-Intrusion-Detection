import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix
import requests
import json

class NIDSEngine:
    def __init__(self):
        self.model = None
        self.X_test = None
        self.y_test = None
        self.df = None
        self.api_key = None
        self.feature_names = None 
        self.base_cols = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 
                          'Packet Length Mean', 'Active Mean', 'Label']

    def configure_ai(self, api_key):
        self.api_key = api_key.strip()
        return True

    def load_data(self, source_type, file_path=None):
        """
        Switchboard for loading data based on user selection.
        """
        if source_type == 'synthetic':
            self.df = self._generate_synthetic()
        elif source_type == 'csv':
            if not file_path: raise ValueError("File path required")
            self.df = self._load_csv(file_path)
        return len(self.df)

    def _generate_synthetic(self):
        """Generates mathematical simulation data."""
        np.random.seed(1337)
        n = 5000
        data = {
            'Destination Port': np.random.randint(1, 65535, n),
            'Flow Duration': np.random.randint(100, 100000, n),
            'Total Fwd Packets': np.random.randint(1, 100, n),
            'Packet Length Mean': np.random.uniform(10, 1500, n),
            'Active Mean': np.random.uniform(0, 1000, n),
            'Label': np.random.choice([0, 1], size=n, p=[0.7, 0.3]) 
        }
        df = pd.DataFrame(data)
        # Inject patterns
        attacks = df['Label'] == 1
        df.loc[attacks, 'Total Fwd Packets'] += np.random.randint(50, 300, size=attacks.sum())
        return df

    def _load_csv(self, file_path):
        """
        Loads and cleans a Real CIC-IDS2017 CSV.
        """
        # Read CSV (handling spaces in headers which CIC dataset has)
        df = pd.read_csv(file_path, nrows=100000) 
        
        # 1. Clean Column Names (Strip spaces)
        df.columns = df.columns.str.strip()
        
        existing = [c for c in self.base_cols if c in df.columns]
        df = df[existing].dropna()
        if 'Label' in df.columns and df['Label'].dtype == 'object':
            df['Label'] = df['Label'].apply(lambda x: 0 if 'BENIGN' in str(x).upper() else 1)
        
        # Ensure mix of classes if possible (Subsampling)
        # If the dataset is purely one class, training won't create a nice confusion matrix.
        return df

    def train(self, split_ratio, trees):
        if self.df is None: raise ValueError("No data loaded.")
        X = self.df.drop('Label', axis=1, errors='ignore')
        y = self.df['Label']
        self.feature_names = X.columns.tolist()
        
        test_size = (100 - split_ratio) / 100.0
        X_train, self.X_test, y_train, self.y_test = train_test_split(X, y, test_size=test_size, random_state=42)
        
        self.model = RandomForestClassifier(n_estimators=trees, random_state=42)
        self.model.fit(X_train, y_train)

    def get_metrics(self):
        if not self.model: return None
        preds = self.model.predict(self.X_test)
        return {
            'accuracy': accuracy_score(self.y_test, preds),
            'cm': confusion_matrix(self.y_test, preds),
            'threats': np.sum(preds)
        }

    def get_random_test_packet(self):
        if self.X_test is None: return None, None
        idx = np.random.randint(0, len(self.X_test))
        return self.X_test.iloc[idx], self.y_test.iloc[idx]

    def construct_manual_packet(self, duration, packets, length, active):
        if self.feature_names is None: return None
        data = {col: 0 for col in self.feature_names}
        data['Flow Duration'] = duration
        data['Total Fwd Packets'] = packets
        data['Packet Length Mean'] = length
        data['Active Mean'] = active
        data['Destination Port'] = 80
        return pd.DataFrame([data])

    def predict_packet(self, packet_data):
        if not self.model: return -1
        if isinstance(packet_data, (pd.Series, dict)):
             data_dict = packet_data.to_dict() if hasattr(packet_data, 'to_dict') else packet_data
             ordered = {k: [data_dict.get(k, 0)] for k in self.feature_names}
             packet_df = pd.DataFrame(ordered)
        else:
            packet_df = packet_data
        return self.model.predict(packet_df)[0]

    def ask_groq(self, packet_data, prediction):
        if not self.api_key: return "⚠️ Error: Groq API Key Not Configured."
        status = "MALICIOUS (ATTACK)" if prediction == 1 else "BENIGN (SAFE)"
        
        if isinstance(packet_data, pd.DataFrame): pkt_str = packet_data.iloc[0].to_string()
        elif isinstance(packet_data, pd.Series): pkt_str = packet_data.to_string()
        else: pkt_str = str(packet_data)

        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        
        system_role = "You are a Senior Network Security Analyst. Output strictly in bullet points."
        user_msg = f"""
        Analyze this packet. Classification: {status}
        Packet Header Data:
        {pkt_str}
        FORMAT YOUR RESPONSE LIKE THIS:
        ### Analysis Logic
        * **[Metric Name]**: Explanation of why value indicates {status}.
        * **[Metric Name]**: Secondary indicator explanation.
        
        ### Conclusion
        One final forensic sentence.
        """
        payload = {
            "messages": [{"role": "system", "content": system_role}, {"role": "user", "content": user_msg}],
            "model": "llama-3.3-70b-versatile",
            "temperature": 0.3,
            "max_tokens": 400
        }
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=12)
            if response.status_code == 200: return response.json()['choices'][0]['message']['content']
            else: return f"Groq API Error {response.status_code}: {response.text}"
        except Exception as e:
            return f"Connection Failed: {str(e)}"