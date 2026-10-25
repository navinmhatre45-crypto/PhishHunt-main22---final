# train_model.py
import re
import pandas as pd
import numpy as np
import os
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import VotingClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
import joblib

# Set the file path for the trained model
MODEL_PATH = "phishing_model.pkl"

# --- NEW: Configuration for Sampling ---
# Set the maximum number of rows to train the model on.
# Set this to None to use the entire dataset.
MAX_SAMPLES = 100000 
# ---------------------------------------

def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_special'] = sum(c in ['@', '-', '_', '?', '=', '&', '%'] for c in url)
    features['has_https'] = 1 if url.lower().startswith("https") else 0
    # Simple IP regex check
    features['has_ip'] = 1 if re.match(r'http[s]?://\d+\.\d+\.\d+\.\d+', url) else 0
    # Check for suspicious Top-Level Domains (TLDs)
    features['suspicious_tld'] = 1 if any(tld in url for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']) else 0
    return features

# ----------------------------------------------------------------------
# --- DATASET LOADING LOGIC (Updated to load CSV & Sample) ---
# ----------------------------------------------------------------------
DATASET_PATH = 'phishing_site_urls.csv' 
URL_COL_NAME = 'URL'     # Name of the column in your CSV containing the URL string
LABEL_COL_NAME = 'Label' # Name of the column in your CSV containing the target (0 or 1)

if not os.path.exists(DATASET_PATH):
    print(f"ERROR: Dataset file not found at '{DATASET_PATH}'.")
    print("Please make sure your large dataset CSV is in the same directory.")
    exit()

try:
    print(f"Loading large dataset from {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH, encoding='latin1')

    # Data Cleaning and Column Preparation:
    if 'URL' in df.columns: df.rename(columns={'URL': URL_COL_NAME}, inplace=True)
    if 'Class' in df.columns: df.rename(columns={'Class': LABEL_COL_NAME}, inplace=True)
    elif 'class' in df.columns: df.rename(columns={'class': LABEL_COL_NAME}, inplace=True)
    elif 'Target' in df.columns: df.rename(columns={'Target': LABEL_COL_NAME}, inplace=True)

    if URL_COL_NAME not in df.columns or LABEL_COL_NAME not in df.columns:
        print(f"ERROR: Could not find required columns ('{URL_COL_NAME}' and '{LABEL_COL_NAME}') in the dataset.")
        print("Available columns:", df.columns.tolist())
        exit()

    # FIX: MAP STRING LABELS TO INTEGERS (From previous correction)
    label_map = {
        'bad': 1, 'phishing': 1, '1': 1, 
        'good': 0, 'legitimate': 0, '0': 0
    }
    df[LABEL_COL_NAME] = df[LABEL_COL_NAME].astype(str).str.lower().map(label_map)
    
    # Drop any remaining NaNs (including those created by failed label mapping)
    df.dropna(subset=[URL_COL_NAME, LABEL_COL_NAME], inplace=True)
    df = df[df[URL_COL_NAME].astype(bool)]
    df[LABEL_COL_NAME] = df[LABEL_COL_NAME].astype(int) # Ensure target is integer

    initial_size = len(df)
    
    # --- FIXED SAMPLING LOGIC: Use train_test_split for stratified sampling ---
    if MAX_SAMPLES is not None and initial_size > MAX_SAMPLES:
        print(f"Dataset size ({initial_size}) exceeds MAX_SAMPLES ({MAX_SAMPLES}).")
        print("Performing stratified random sampling using train_test_split workaround...")
        
        # Calculate the fraction of the data to keep
        sample_fraction = MAX_SAMPLES / initial_size
        
        # train_test_split is used here to get a stratified subset
        df_sampled, _ = train_test_split(
            df, 
            train_size=sample_fraction, # This will keep the correct proportion of rows
            random_state=42, 
            stratify=df[LABEL_COL_NAME]
        )
        df = df_sampled # Replace the original DataFrame with the sampled one
    # --- END SAMPLING LOGIC ---

    print(f"Dataset ready. Total rows for training: {len(df)}")

except Exception as e:
    print(f"An error occurred while loading or processing the dataset: {e}")
    exit()


# ----------------------------------------------------------------------
# --- MODEL TRAINING LOGIC (Existing code remains unchanged) ---
# ----------------------------------------------------------------------

# Extract features and target variables
X = pd.DataFrame([extract_features(u) for u in df[URL_COL_NAME]])
y = df[LABEL_COL_NAME]

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
# Note: stratify=y here ensures the train/test split is also balanced.

# Build estimator components
lr = LogisticRegression(max_iter=1000)
svc = SVC(probability=True)
dt = DecisionTreeClassifier(random_state=42)

# Voting ensemble (Hybrid Model)
ensemble = VotingClassifier(estimators=[
    ('lr', lr),
    ('svc', svc),
    ('dt', dt)
], voting='soft')

# Use pipeline with scaler
pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('clf', ensemble)
])

# Grid for hyperparams 
param_grid = {
    'clf__lr__C': [0.1, 1], 
    'clf__svc__C': [0.1, 1],
    'clf__dt__max_depth': [3, 6] 
    # Reduced the grid slightly for faster training with the large sample
}

# GridSearchCV performs the cross-validation search
search = GridSearchCV(pipeline, param_grid, cv=3, n_jobs=-1, verbose=1)
search.fit(X_train, y_train)

print("\n--- Training Complete ---")
print("Best params:", search.best_params_)
best = search.best_estimator_

# Cross-val score on the full training set
scores = cross_val_score(best, X, y, cv=5)
print(f"Final 5-Fold Cross-Validation Accuracy: {scores.mean():.4f} (+/- {scores.std() * 2:.4f})")

# Evaluate on the test set
y_pred = best.predict(X_test)
print("\nAccuracy Score on Test Set:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# Save the best model and the scaler/pipeline together
print(f"Saving the final model to {MODEL_PATH}")
joblib.dump(best, MODEL_PATH)

print("Model training and saving process finished successfully.")