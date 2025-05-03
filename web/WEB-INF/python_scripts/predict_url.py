# predict_url.py
import sys
import pickle
import numpy as np
import warnings
from feature import FeatureExtraction

# Redirect warnings to null device
warnings.filterwarnings('ignore')

def predict_url(url):
    try:
        # Load the model
        with open("phishing_detector_model.pkl", "rb") as file:
            model_info = pickle.load(file)
        
        gbc = model_info['model']
        scaler = model_info['scaler']
        
        # Extract features
        feature_extractor = FeatureExtraction(url)
        features = feature_extractor.getFeaturesList()
        
        # Transform features
        x = np.array(features).reshape(1,30)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            x_scaled = scaler.transform(x)
        
        # Get prediction and probability
        prediction = gbc.predict(x_scaled)[0]
        probability = gbc.predict_proba(x_scaled)[0]
        
        # Format result as JSON-style string
        result = f"RESULT:{{'safe':{prediction == 1},'confidence':{float(max(probability)):.3f}}}"
        print(result)
        return 0
    except Exception as e:
        print(f"ERROR:{{'message':'{str(e)}'}}")
        return 1

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("ERROR:{'message':'Invalid number of arguments'}")
        sys.exit(1)
    
    url = sys.argv[1]
    sys.exit(predict_url(url))