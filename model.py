import numpy as np
import os
import pickle
import random
from collections import deque
import torch
import torch.nn as nn
import torch.optim as optim

class CNNModel(nn.Module):
    def __init__(self, input_dim):
        super(CNNModel, self).__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.network(x)

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
        self.device = torch.device("cpu")  # Use CPU for FPGA compatibility

    def build_model(self, input_dim):
        self.input_dim = input_dim
        self.model = CNNModel(input_dim).to(self.device)
        self.optimizer = optim.Adam(self.model.parameters())
        self.criterion = nn.BCELoss()
        self.model_initialized = True
        return self.model

    def train(self, X_train, y_train, X_val=None, y_val=None, epochs=10, batch_size=32):
        if not self.model_initialized:
            self.build_model(X_train.shape[1])

        # Convert to tensors
        X_train = torch.FloatTensor(X_train).to(self.device)
        y_train = torch.FloatTensor(y_train).to(self.device)

        for epoch in range(epochs):
            self.model.train()
            self.optimizer.zero_grad()
            outputs = self.model(X_train)
            loss = self.criterion(outputs.squeeze(), y_train)
            loss.backward()
            self.optimizer.step()

        return {'accuracy': (outputs.round() == y_train).float().mean().item()}

    def predict(self, features):
        if not self.model_initialized:
            is_malicious = random.random() > 0.8
            confidence = random.uniform(0.6, 0.9)
            return is_malicious, confidence

        # Convert to tensor
        if isinstance(features, list):
            features = np.array(features)
        if len(features.shape) == 1:
            features = features.reshape(1, -1)

        features = torch.FloatTensor(features).to(self.device)

        try:
            self.model.eval()
            with torch.no_grad():
                output = self.model(features)
                confidence = float(output[0])
                is_malicious = confidence > 0.5
                return is_malicious, confidence
        except Exception as e:
            print(f"Prediction error: {str(e)}")
            is_malicious = random.random() > 0.8
            confidence = random.uniform(0.6, 0.9)
            return is_malicious, confidence

    def save(self, model_path='model.pkl', metadata_path='model_metadata.pkl'):
        if not self.model_initialized:
            raise ValueError("Cannot save an uninitialized model")

        torch.save({
            'model_state_dict': self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
        }, model_path)

        metadata = {
            'input_dim': self.input_dim,
            'epsilon': self.epsilon,
            'epsilon_min': self.epsilon_min,
            'epsilon_decay': self.epsilon_decay,
            'gamma': self.gamma,
            'train_step_counter': self.train_step_counter
        }

        with open(metadata_path, 'wb') as f:
            pickle.dump(metadata, f)

    def load(self, model_path='model.pkl', metadata_path='model_metadata.pkl'):
        try:
            if os.path.exists(model_path):
                checkpoint = torch.load(model_path)
                if not self.model_initialized:
                    self.build_model(self.input_dim)
                self.model.load_state_dict(checkpoint['model_state_dict'])
                self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
                self.model_initialized = True

                if os.path.exists(metadata_path):
                    with open(metadata_path, 'rb') as f:
                        metadata = pickle.load(f)

                    self.input_dim = metadata.get('input_dim', self.input_dim)
                    self.epsilon = metadata.get('epsilon', self.epsilon)
                    self.epsilon_min = metadata.get('epsilon_min', self.epsilon_min)
                    self.epsilon_decay = metadata.get('epsilon_decay', self.epsilon_decay)
                    self.gamma = metadata.get('gamma', self.gamma)
                    self.train_step_counter = metadata.get('train_step_counter', 0)

                return True
            else:
                print(f"Model file not found: {model_path}")
                return False
        except Exception as e:
            print(f"Error loading model: {str(e)}")
            return False