import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from data_preprocessing import DataPreprocessor
from model import RLModel
from utils import save_model, evaluate_model_performance
import time

def train_model(dataset_path, train_ratio=0.8, val_ratio=0.1, test_ratio=0.1):
    """
    Train a new model on the CICIoT2023 dataset
    
    Parameters:
    - dataset_path: Path to the CICIoT2023 dataset
    - train_ratio: Ratio of data to use for training
    - val_ratio: Ratio of data to use for validation
    - test_ratio: Ratio of data to use for testing
    
    Returns:
    - Trained model and performance metrics
    """
    print("Starting model training...")
    
    # Validate ratios
    assert train_ratio + val_ratio + test_ratio == 1.0, "Ratios must sum to 1"
    
    # Initialize data preprocessor
    preprocessor = DataPreprocessor()
    
    # Load dataset
    try:
        print(f"Loading dataset from {dataset_path}...")
        df = preprocessor.load_dataset(dataset_path)
        print(f"Dataset loaded with shape: {df.shape}")
    except Exception as e:
        print(f"Error loading dataset: {str(e)}")
        raise
    
    # Data cleaning
    df_clean = preprocessor.clean_data(df)
    
    # Identify target column
    target_column = None
    potential_targets = ['label', 'class', 'attack_type', 'is_attack', 'is_malicious']
    
    for col in potential_targets:
        if col in df_clean.columns:
            target_column = col
            break
    
    if not target_column:
        raise ValueError("Could not identify target column in dataset. Expected one of: 'label', 'class', 'attack_type', 'is_attack', 'is_malicious'")
    
    print(f"Using '{target_column}' as target column")
    
    # Preprocess data
    X, y = preprocessor.preprocess_data(df_clean, target_column=target_column, train=True)
    
    # Split data
    X_train, X_val, X_test, y_train, y_val, y_test = preprocessor.split_train_val_test(
        X, y, 
        train_ratio=train_ratio, 
        val_ratio=val_ratio, 
        test_ratio=test_ratio
    )
    
    # Initialize the model
    model = RLModel()
    model.build_model(X_train.shape[1])
    
    # Initial supervised training
    print("Starting supervised pre-training...")
    start_time = time.time()
    
    history = model.train(
        X_train, y_train,
        X_val=X_val, y_val=y_val,
        epochs=10,
        batch_size=32
    )
    
    training_time = time.time() - start_time
    print(f"Supervised pre-training completed in {training_time:.2f} seconds")
    
    # Reinforcement learning fine-tuning
    print("Starting reinforcement learning fine-tuning...")
    start_time = time.time()
    
    # Prepare data for RL
    for i in range(len(X_train)):
        state = np.array([X_train.iloc[i].values]) if hasattr(X_train, 'iloc') else np.array([X_train[i]])
        action = int(y_train.iloc[i]) if hasattr(y_train, 'iloc') else int(y_train[i])
        reward = 1.0 if action == 1 else 0.1  # Higher reward for detecting malicious
        next_state = state  # In standalone detection, next state equals current state
        done = True         # Each packet is an episode
        
        # Add to replay memory
        model.remember(state, action, reward, next_state, done)
        
        # Periodically replay and update model
        if (i + 1) % 100 == 0 or i == len(X_train) - 1:
            model.replay(batch_size=min(32, len(model.memory)))
    
    rl_time = time.time() - start_time
    print(f"Reinforcement learning fine-tuning completed in {rl_time:.2f} seconds")
    
    # Evaluate model
    print("Evaluating model performance...")
    metrics = evaluate_model_performance(model, X_test, y_test)
    
    # Print metrics
    print("\nModel Performance Metrics:")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall: {metrics['recall']:.4f}")
    print(f"F1 Score: {metrics['f1']:.4f}")
    print(f"False Positive Rate: {metrics['false_positive_rate']:.4f}")
    
    # Save model and preprocessor
    print("Saving model and preprocessor...")
    save_model(model)
    preprocessor.save_preprocessor()
    
    print("Training complete!")
    
    return model, metrics

def retrain_model(model, feedback_data):
    """
    Retrain an existing model with feedback data
    
    Parameters:
    - model: Existing RL model
    - feedback_data: List of dictionaries with features and labels
    
    Returns:
    - Retrained model
    """
    if not feedback_data:
        print("No feedback data provided for retraining")
        return model, None
    
    print(f"Retraining model with {len(feedback_data)} feedback samples...")
    
    # Extract features and labels
    X = np.array([item['features'] for item in feedback_data])
    y = np.array([item['label'] for item in feedback_data])
    
    # Split data for evaluation
    if len(X) >= 5:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
    else:
        X_train, X_test, y_train, y_test = X, X, y, y
    
    # Retrain the model
    success = model.retrain_with_feedback(feedback_data)
    
    if not success:
        print("Retraining failed")
        return model, None
    
    # Evaluate performance if we have enough test data
    metrics = None
    if len(X_test) > 0:
        print("Evaluating retrained model...")
        metrics = evaluate_model_performance(model, X_test, y_test)
        
        print("\nRetrained Model Performance Metrics:")
        print(f"Accuracy: {metrics['accuracy']:.4f}")
        print(f"Precision: {metrics['precision']:.4f}")
        print(f"Recall: {metrics['recall']:.4f}")
        print(f"F1 Score: {metrics['f1']:.4f}")
        print(f"False Positive Rate: {metrics['false_positive_rate']:.4f}")
    
    # Save the retrained model
    save_model(model)
    
    print("Retraining complete!")
    
    return model, metrics

if __name__ == "__main__":
    # Example usage
    dataset_path = "data/CICIoT2023.csv"
    
    if os.path.exists(dataset_path):
        model, metrics = train_model(dataset_path)
        print("Model trained successfully!")
    else:
        print(f"Dataset not found at {dataset_path}")
