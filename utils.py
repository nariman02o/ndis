import os
import pickle
import json
import pandas as pd
from datetime import datetime
import numpy as np

def load_model(model, model_path='model.h5', metadata_path='model_metadata.pkl'):
    """
    Load a trained model and its metadata
    Returns True if successful, False otherwise
    """
    if not os.path.exists(model_path):
        print(f"Model file not found: {model_path}")
        return False
    
    try:
        success = model.load(model_path, metadata_path)
        return success
    except Exception as e:
        print(f"Error loading model: {str(e)}")
        return False

def save_model(model, model_path='model.h5', metadata_path='model_metadata.pkl'):
    """
    Save a trained model and its metadata
    Returns True if successful, False otherwise
    """
    try:
        model.save(model_path, metadata_path)
        return True
    except Exception as e:
        print(f"Error saving model: {str(e)}")
        return False

def load_dataset(file_path):
    """
    Load a dataset from a file
    Returns a pandas DataFrame
    """
    try:
        if file_path.lower().endswith('.csv'):
            df = pd.read_csv(file_path)
        elif file_path.lower().endswith(('.xls', '.xlsx')):
            df = pd.read_excel(file_path)
        elif file_path.lower().endswith('.json'):
            df = pd.read_json(file_path)
        else:
            raise ValueError(f"Unsupported file format: {file_path}")
        
        return df
    except Exception as e:
        print(f"Error loading dataset: {str(e)}")
        raise

def save_json(data, file_path):
    """
    Save data to a JSON file
    """
    try:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving JSON: {str(e)}")
        return False

def load_json(file_path):
    """
    Load data from a JSON file
    """
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return data
    except Exception as e:
        print(f"Error loading JSON: {str(e)}")
        return None

def update_detection_history(history, packet, features, is_malicious, confidence, max_history=1000):
    """
    Update the detection history with a new packet detection
    """
    # Create detection entry
    detection = {
        'timestamp': datetime.now().isoformat(),
        'src_ip': packet.get('src', 'unknown'),
        'dst_ip': packet.get('dst', 'unknown'),
        'src_port': packet.get('sport', 0),
        'dst_port': packet.get('dport', 0),
        'protocol': packet.get('proto', 'unknown'),
        'length': packet.get('len', 0),
        'is_malicious': bool(is_malicious),
        'confidence': float(confidence),
        'features': features.tolist() if isinstance(features, np.ndarray) else features
    }
    
    # Add to history
    history.append(detection)
    
    # Trim history if it exceeds max size
    if len(history) > max_history:
        history.pop(0)  # Remove the oldest entry
    
    return history

def prepare_feedback_data(feedback_items):
    """
    Prepare feedback data for model retraining
    """
    if not feedback_items:
        return None
    
    # Extract features and labels
    X = []
    y = []
    
    for item in feedback_items:
        X.append(item['features'])
        y.append(item['label'])
    
    return np.array(X), np.array(y)

def evaluate_model_performance(model, X_test, y_test):
    """
    Evaluate model performance on test data
    Returns a dictionary of performance metrics
    """
    predictions = []
    confidences = []
    
    # Get predictions for each sample
    for x in X_test:
        is_malicious, confidence = model.predict(x)
        predictions.append(1 if is_malicious else 0)
        confidences.append(confidence)
    
    # Calculate metrics
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
    
    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, zero_division=0)
    recall = recall_score(y_test, predictions, zero_division=0)
    f1 = f1_score(y_test, predictions, zero_division=0)
    
    # Calculate false positive rate
    tn, fp, fn, tp = confusion_matrix(y_test, predictions, labels=[0, 1]).ravel()
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    # Return metrics dictionary
    return {
        'accuracy': float(accuracy),
        'precision': float(precision),
        'recall': float(recall),
        'f1': float(f1),
        'false_positive_rate': float(false_positive_rate),
        'true_positives': int(tp),
        'false_positives': int(fp),
        'true_negatives': int(tn),
        'false_negatives': int(fn)
    }
