import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, MinMaxScaler, OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
import pickle

class DataPreprocessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.min_max_scaler = MinMaxScaler()
        self.categorical_encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore')
        self.imputer = SimpleImputer(strategy='mean')
        self.feature_names = None
        self.categorical_features = None
        self.numerical_features = None
        
    def load_dataset(self, file_path):
        """
        Load the CICIoT2023 dataset
        """
        print(f"Loading dataset from {file_path}...")
        try:
            df = pd.read_csv(file_path)
            print(f"Dataset loaded successfully with shape: {df.shape}")
            return df
        except Exception as e:
            print(f"Error loading dataset: {str(e)}")
            raise
    
    def clean_data(self, df):
        """
        Clean the dataset by removing duplicates, handling missing values, etc.
        """
        print("Cleaning dataset...")
        
        # Make a copy to avoid modifying the original
        df_clean = df.copy()
        
        # Drop duplicates
        df_clean = df_clean.drop_duplicates()
        
        # Handle missing values
        df_clean = df_clean.replace([np.inf, -np.inf], np.nan)
        
        # Identify numerical features for imputation
        numerical_features = df_clean.select_dtypes(include=['int64', 'float64']).columns
        self.numerical_features = numerical_features.tolist()
        
        # Impute missing values for numerical features
        if numerical_features.size > 0:
            df_clean[numerical_features] = self.imputer.fit_transform(df_clean[numerical_features])
        
        # Identify categorical features
        categorical_features = df_clean.select_dtypes(include=['object', 'category']).columns
        self.categorical_features = categorical_features.tolist()
        
        print(f"Data cleaned. Shape after cleaning: {df_clean.shape}")
        return df_clean
    
    def preprocess_data(self, df, target_column='label', train=True):
        """
        Preprocess the dataset for training or prediction
        """
        print("Preprocessing data...")
        
        # Separate features and target
        if target_column in df.columns:
            X = df.drop(columns=[target_column])
            y = df[target_column]
            
            # Convert target to binary (0: benign, 1: malicious)
            if train:
                # Check if target is already binary
                unique_values = y.unique()
                if len(unique_values) > 2:
                    # If not binary, convert to binary (benign vs malicious)
                    y = y.apply(lambda x: 0 if x.lower() == 'benign' else 1)
                elif not all(val in [0, 1] for val in unique_values):
                    # If binary but not 0/1 format
                    y = y.map({unique_values[0]: 0, unique_values[1]: 1})
        else:
            X = df
            y = None
        
        # Save feature names
        self.feature_names = X.columns.tolist()
        
        # Handle categorical features if present
        if self.categorical_features and len(self.categorical_features) > 0:
            # Filter to only include columns that exist in X
            valid_cat_features = [col for col in self.categorical_features if col in X.columns]
            
            if valid_cat_features:
                if train:
                    # Fit and transform categorical features
                    encoded_cats = self.categorical_encoder.fit_transform(X[valid_cat_features])
                else:
                    # Only transform using previously fit encoder
                    encoded_cats = self.categorical_encoder.transform(X[valid_cat_features])
                
                # Get encoded feature names
                cat_feature_names = self.categorical_encoder.get_feature_names_out(valid_cat_features)
                
                # Create DataFrame with encoded features
                encoded_df = pd.DataFrame(
                    encoded_cats, 
                    columns=cat_feature_names, 
                    index=X.index
                )
                
                # Drop original categorical columns and add encoded ones
                X = X.drop(columns=valid_cat_features)
                X = pd.concat([X, encoded_df], axis=1)
        
        # Handle numerical features
        if self.numerical_features and len(self.numerical_features) > 0:
            # Filter to only include columns that exist in X
            valid_num_features = [col for col in self.numerical_features if col in X.columns]
            
            if valid_num_features:
                if train:
                    # Fit and transform numerical features
                    X[valid_num_features] = self.scaler.fit_transform(X[valid_num_features])
                else:
                    # Only transform using previously fit scaler
                    X[valid_num_features] = self.scaler.transform(X[valid_num_features])
        
        print(f"Data preprocessing complete. Features shape: {X.shape}")
        
        if y is not None:
            return X, y
        else:
            return X
    
    def split_train_val_test(self, X, y, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, random_state=42):
        """
        Split the data into training, validation, and test sets
        """
        assert train_ratio + val_ratio + test_ratio == 1.0, "Ratios must sum to 1"
        
        # First split: separate test set
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_ratio, random_state=random_state, stratify=y
        )
        
        # Second split: separate validation set from the remaining data
        val_ratio_adjusted = val_ratio / (train_ratio + val_ratio)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_ratio_adjusted, random_state=random_state, stratify=y_temp
        )
        
        print(f"Data split complete. Shapes - Train: {X_train.shape}, Val: {X_val.shape}, Test: {X_test.shape}")
        
        return X_train, X_val, X_test, y_train, y_val, y_test
    
    def save_preprocessor(self, file_path='preprocessor.pkl'):
        """
        Save the preprocessor to disk
        """
        preprocessor_data = {
            'scaler': self.scaler,
            'min_max_scaler': self.min_max_scaler,
            'categorical_encoder': self.categorical_encoder,
            'imputer': self.imputer,
            'feature_names': self.feature_names,
            'categorical_features': self.categorical_features,
            'numerical_features': self.numerical_features
        }
        
        with open(file_path, 'wb') as f:
            pickle.dump(preprocessor_data, f)
        
        print(f"Preprocessor saved to {file_path}")
    
    def load_preprocessor(self, file_path='preprocessor.pkl'):
        """
        Load the preprocessor from disk
        """
        try:
            with open(file_path, 'rb') as f:
                preprocessor_data = pickle.load(f)
            
            self.scaler = preprocessor_data['scaler']
            self.min_max_scaler = preprocessor_data['min_max_scaler']
            self.categorical_encoder = preprocessor_data['categorical_encoder']
            self.imputer = preprocessor_data['imputer']
            self.feature_names = preprocessor_data['feature_names']
            self.categorical_features = preprocessor_data['categorical_features']
            self.numerical_features = preprocessor_data['numerical_features']
            
            print(f"Preprocessor loaded from {file_path}")
            return True
        except Exception as e:
            print(f"Error loading preprocessor: {str(e)}")
            return False

# Utility function to prepare a single packet for prediction
def prepare_packet_features(packet_data, preprocessor):
    """
    Prepare a single packet's features for prediction using the trained preprocessor
    """
    # Convert packet data to DataFrame (single row)
    packet_df = pd.DataFrame([packet_data])
    
    # Apply the same preprocessing steps as during training
    processed_features = preprocessor.preprocess_data(packet_df, train=False)
    
    return processed_features
