import sys
import pickle
import numpy as np
import warnings
import json
import logging
import traceback
from feature import FeatureExtraction
import urllib.parse

# Setup logging
logging.basicConfig(filename='phishing_predictor.log', level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Redirect warnings to null device
warnings.filterwarnings('ignore')

def predict_url(url):
    try:
        # URL decode if needed
        if '%' in url:
            url = urllib.parse.unquote(url)
            
        logging.debug(f"Processing URL: {url}")
        
        # Load the model - try to load only once if script is executed multiple times
        try:
            with open("phishing_detector_model.pkl", "rb") as file:
                model_info = pickle.load(file)
            
            gbc = model_info['model']
            scaler = model_info['scaler']
            
            logging.debug(f"Model loaded successfully, type: {type(gbc).__name__}")
            logging.debug(f"Scaler loaded successfully, type: {type(scaler).__name__}")
        except Exception as e:
            logging.error(f"Error loading model: {str(e)}", exc_info=True)
            error_message = f"Failed to load model: {str(e)}"
            print(json.dumps({"error": error_message}))
            return 1
            
        # Extract features
        try:
            feature_extractor = FeatureExtraction(url)
            features = feature_extractor.getFeaturesList()
            
            # Verify we have the expected number of features
            if len(features) != 30:
                error_msg = f"Expected 30 features, got {len(features)}"
                logging.error(error_msg)
                print(f"RESULT:{json.dumps({'safe': False, 'confidence': 0.0, 'error': error_msg})}")
                return 1
                
            logging.debug(f"Features extracted successfully: {features}")
        except Exception as e:
            logging.error(f"Feature extraction error: {str(e)}", exc_info=True)
            print(f"RESULT:{json.dumps({'safe': False, 'confidence': 0.0, 'error': str(e)})}")
            return 1
        
        # Transform features
        try:
            x = np.array(features).reshape(1, 30)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                x_scaled = scaler.transform(x)
            
            # Get prediction and probability
            prediction = gbc.predict(x_scaled)[0]
            probability = gbc.predict_proba(x_scaled)[0]
            
            logging.debug(f"Raw prediction: {prediction}, probabilities: {probability}")
            
            # Format result as proper JSON using the json module
            confidence = float(max(probability))
            result = {
                "safe": bool(prediction == 1),
                "confidence": round(confidence, 3)
            }
            
            print(f"RESULT:{json.dumps(result)}")
            logging.debug(f"Final result: {result}")
            return 0
        except Exception as e:
            logging.error(f"Prediction error: {str(e)}", exc_info=True)
            print(f"RESULT:{json.dumps({'safe': False, 'confidence': 0.0, 'error': str(e)})}")
            return 1
    except Exception as e:
        error_message = str(e)
        logging.error(f"Unhandled error: {error_message}", exc_info=True)
        print(f"RESULT:{json.dumps({'safe': False, 'confidence': 0.0, 'error': error_message})}")
        return 1

if __name__== "__main__":
    if len(sys.argv) != 2:
        print(f"RESULT:{json.dumps({'safe': False, 'confidence': 0.0, 'error': 'Invalid number of arguments'})}")
        sys.exit(1)
    
    url = sys.argv[1]
    sys.exit(predict_url(url))