# Update predict.py to ensure it always prints something
import sys
import joblib

def predict_url(url, model_path, vectorizer_path):
    try:
        # Load the model and vectorizer
        model = joblib.load(model_path)
        vectorizer = joblib.load(vectorizer_path)
        
        # Transform the URL
        url_transformed = vectorizer.transform([url])
        
        # Make prediction
        prediction = model.predict(url_transformed)[0]
        
        print(prediction)
    except Exception as e:
        print(f"Prediction Error: {str(e)}")
        sys.stderr.write(f"Prediction Error: {str(e)}\n")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Error: Invalid number of arguments")
        sys.exit(1)
        
    url = sys.argv[1]
    model_path = sys.argv[2]
    vectorizer_path = sys.argv[3]
    
    predict_url(url, model_path, vectorizer_path)