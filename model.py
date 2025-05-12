import numpy as np
import os
import pickle
import random
from collections import deque
from sklearn.ensemble import RandomForestClassifier

class RLModel:
    """
    Reinforcement Learning-based model for Network Intrusion Detection
    Simplified implementation using RandomForest for demo purposes
    """
    def __init__(self, input_dim=100, memory_size=1000, gamma=0.95, epsilon=1.0, epsilon_min=0.01, epsilon_decay=0.995):
        self.input_dim = input_dim  # Will be updated when initialized with data
        self.memory_size = memory_size
        self.memory = deque(maxlen=memory_size)
        self.gamma = gamma  # Discount factor
        self.epsilon = epsilon  # Exploration rate
        self.epsilon_min = epsilon_min
        self.epsilon_decay = epsilon_decay
        self.model = None
        self.model_initialized = False
        self.batch_size = 32
        self.train_step_counter = 0
        
    def build_model(self, input_dim):
        """
        Build a RandomForest model (simpler than DQN for demo)
        """
        self.input_dim = input_dim
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model_initialized = True
        return self.model
    
    def remember(self, state, action, reward, next_state, done):
        """
        Store experience in memory for replay
        """
        self.memory.append((state, action, reward, next_state, done))
    
    def choose_action(self, state):
        """
        Choose action based on epsilon-greedy policy
        """
        if np.random.rand() <= self.epsilon:
            return random.randrange(2)  # Random choice between 0 and 1
        
        if not self.model_initialized:
            return 0
            
        # Return the predicted class
        return self.model.predict(state)[0]
    
    def replay(self, batch_size=None):
        """
        Update model with replay data
        """
        if batch_size is None:
            batch_size = self.batch_size
            
        if len(self.memory) < batch_size:
            return
        
        # Sample random experiences from memory
        minibatch = random.sample(self.memory, batch_size)
        
        # Extract states and actions for training
        states = []
        actions = []
        for state, action, reward, next_state, done in minibatch:
            states.append(state[0])  # Remove batch dimension
            actions.append(action)
        
        # Update model if we have enough data
        if len(states) > 0 and self.model_initialized:
            self.model.fit(np.array(states), np.array(actions))
        
        # Decay epsilon for less exploration over time
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
        
        # Update step counter
        self.train_step_counter += 1
    
    def train(self, X_train, y_train, X_val=None, y_val=None, epochs=10, batch_size=32):
        """
        Train the model with supervised learning
        """
        if not self.model_initialized:
            self.build_model(X_train.shape[1])
        
        # Convert to numpy arrays if they are pandas dataframes
        if hasattr(X_train, 'values'):
            X_train = X_train.values
        if hasattr(y_train, 'values'):
            y_train = y_train.values
        
        # Train the model
        self.model.fit(X_train, y_train)
        
        # Add some examples to memory for RL
        for i in range(min(1000, len(X_train))):
            state = np.array([X_train[i]])
            action = int(y_train[i])
            reward = 1.0 if action == 1 else 0.0
            next_state = state
            done = True
            self.remember(state, action, reward, next_state, done)
        
        return {'accuracy': self.model.score(X_train, y_train)}
    
    def predict(self, features):
        """
        Predict whether a packet is malicious
        Returns:
        - is_malicious: boolean
        - confidence: float between 0 and 1
        """
        if not self.model_initialized:
            # If model not initialized, use a random baseline
            is_malicious = random.random() > 0.8  # 20% chance of being malicious
            confidence = random.uniform(0.6, 0.9)
            return is_malicious, confidence
        
        # Ensure features are in the right format (2D array)
        if isinstance(features, list):
            features = np.array(features)
        if len(features.shape) == 1:
            features = features.reshape(1, -1)
        
        try:
            # Get prediction
            prediction = self.model.predict(features)[0]
            
            # Get probability if available
            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(features)[0]
                confidence = float(proba[prediction])
            else:
                confidence = 0.8  # Default confidence
            
            is_malicious = bool(prediction)
            
            return is_malicious, confidence
        except Exception as e:
            print(f"Prediction error: {str(e)}")
            # Fallback to random baseline
            is_malicious = random.random() > 0.8  # 20% chance of being malicious
            confidence = random.uniform(0.6, 0.9)
            return is_malicious, confidence
    
    def retrain_with_feedback(self, feedback_data):
        """
        Retrain the model with admin feedback
        feedback_data: list of dictionaries with 'features' and 'label' keys
        """
        if not feedback_data:
            return False
        
        # Extract features and labels
        X = np.array([item['features'] for item in feedback_data])
        y = np.array([item['label'] for item in feedback_data])
        
        # Initialize model if needed
        if not self.model_initialized:
            self.build_model(X.shape[1])
        
        # Retrain with additional data
        if len(X) >= 5:
            self.model.fit(X, y)
        
        # Add to memory for future use
        for i in range(len(X)):
            state = np.array([X[i]])
            action = y[i]
            reward = 1.0 if action == 1 else 0.0
            next_state = state
            done = True
            self.remember(state, action, reward, next_state, done)
        
        # Do a small replay
        self.replay(batch_size=min(len(self.memory), self.batch_size))
        
        return True
    
    def save(self, model_path='model.pkl', metadata_path='model_metadata.pkl'):
        """
        Save the model and its metadata to disk
        """
        if not self.model_initialized:
            raise ValueError("Cannot save an uninitialized model")
        
        # Save the model
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        
        # Save metadata
        metadata = {
            'input_dim': self.input_dim,
            'epsilon': self.epsilon,
            'epsilon_min': self.epsilon_min,
            'epsilon_decay': self.epsilon_decay,
            'gamma': self.gamma,
            'memory': list(self.memory),
            'train_step_counter': self.train_step_counter
        }
        
        with open(metadata_path, 'wb') as f:
            pickle.dump(metadata, f)
    
    def load(self, model_path='model.pkl', metadata_path='model_metadata.pkl'):
        """
        Load the model and its metadata from disk
        """
        try:
            # Load model
            if os.path.exists(model_path):
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                self.model_initialized = True
            
                # Try to load metadata if available
                if os.path.exists(metadata_path):
                    with open(metadata_path, 'rb') as f:
                        metadata = pickle.load(f)
                    
                    self.input_dim = metadata.get('input_dim', self.input_dim)
                    self.epsilon = metadata.get('epsilon', self.epsilon)
                    self.epsilon_min = metadata.get('epsilon_min', self.epsilon_min)
                    self.epsilon_decay = metadata.get('epsilon_decay', self.epsilon_decay)
                    self.gamma = metadata.get('gamma', self.gamma)
                    self.memory = deque(metadata.get('memory', []), maxlen=self.memory_size)
                    self.train_step_counter = metadata.get('train_step_counter', 0)
                
                return True
            else:
                print(f"Model file not found: {model_path}")
                return False
        except Exception as e:
            print(f"Error loading model: {str(e)}")
            return False