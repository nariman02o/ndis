import numpy as np
import os
import random
from collections import deque
import tensorflow as tf
from tensorflow.keras import layers, models
from tensorflow.keras.models import load_model

class RLModel:
    def __init__(self, input_dim=100, memory_size=1000, gamma=0.95, epsilon=1.0, epsilon_min=0.01, epsilon_decay=0.995):
        self.input_dim = input_dim
        self.memory_size = memory_size
        self.memory = deque(maxlen=memory_size)
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_min = epsilon_min
        self.epsilon_decay = epsilon_decay
        self.model = None
        self.model_initialized = False
        self.batch_size = 32
        self.train_step_counter = 0

    def build_model(self, input_dim):
        """Build a CNN model"""
        self.input_dim = input_dim
        model = models.Sequential([
            layers.Reshape((input_dim, 1), input_shape=(input_dim,)),
            layers.Conv1D(32, 3, activation='relu'),
            layers.Conv1D(64, 3, activation='relu'),
            layers.Flatten(),
            layers.Dense(64, activation='relu'),
            layers.Dense(32, activation='relu'),
            layers.Dense(1, activation='sigmoid')
        ])

        model.compile(optimizer='adam',
                     loss='binary_crossentropy',
                     metrics=['accuracy'])

        self.model = model
        self.model_initialized = True
        return self.model

    def predict(self, features):
        if not self.model_initialized:
            is_malicious = random.random() > 0.8
            confidence = random.uniform(0.6, 0.9)
            return is_malicious, confidence

        if isinstance(features, list):
            features = np.array(features)
        if len(features.shape) == 1:
            features = features.reshape(1, -1)

        try:
            prediction = self.model.predict(features, verbose=0)
            confidence = float(prediction[0][0])
            is_malicious = confidence > 0.5
            return is_malicious, confidence
        except Exception as e:
            print(f"Prediction error: {str(e)}")
            is_malicious = random.random() > 0.8
            confidence = random.uniform(0.6, 0.9)
            return is_malicious, confidence

    def train(self, X_train, y_train, X_val=None, y_val=None, epochs=10, batch_size=32):
        if not self.model_initialized:
            self.build_model(X_train.shape[1])

        if hasattr(X_train, 'values'):
            X_train = X_train.values
        if hasattr(y_train, 'values'):
            y_train = y_train.values

        history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val) if X_val is not None else None,
            epochs=epochs,
            batch_size=batch_size,
            verbose=1
        )

        # Save weights after training
        if not self.save_weights('data/model_weights.h5'):
            print("Failed to save weights!")
            
        return history.history

    def save_weights(self, weights_path='data/model_weights.h5'):
        """Save model weights to H5 format"""
        if not self.model_initialized:
            raise ValueError("Cannot save weights of uninitialized model")
        try:
            # Create data directory if it doesn't exist
            os.makedirs('data', exist_ok=True)
            self.model.save_weights(weights_path)
            print(f"Model weights saved to {weights_path}")
            return True
        except Exception as e:
            print(f"Error saving weights: {str(e)}")
            return False

    def load_weights(self, weights_path='model_weights.h5'):
        """Load model weights from H5 format"""
        if not self.model_initialized:
            raise ValueError("Initialize model before loading weights")
        self.model.load_weights(weights_path)
        print(f"Model weights loaded from {weights_path}")

    def retrain_with_feedback(self, feedback_data):
        if not feedback_data:
            return False

        X = np.array([item['features'] for item in feedback_data])
        y = np.array([item['label'] for item in feedback_data])

        if not self.model_initialized:
            self.build_model(X.shape[1])

        if len(X) >= 5:
            self.model.fit(X, y, epochs=5, verbose=1)
            self.save_weights('model_weights.h5')

        return True