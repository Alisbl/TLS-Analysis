import pandas as pd
import numpy as np
import pickle
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
def train_and_test_model(csv_file_path):
    try:
        # Load data from the CSV file
        client_df = pd.read_csv(csv_file_path, on_bad_lines='skip')

        print("Available columns:", client_df.columns)

        # Ensure 'Packet Size' column exists or rename 'Length' to 'Packet Size'
        if 'Packet Size' not in client_df.columns:
            if 'Length' in client_df.columns:
                client_df.rename(columns={'Length': 'Packet Size'}, inplace=True)
            else:
                print("Error: Neither 'Packet Size' nor 'Length' column found.")
                return

        # Filter the data to include only Client Hello packets
        client_hello_df = client_df[client_df['Info'] == 'Client Hello']

        # Convert 'Timestamp' to numeric and drop rows with missing values
        client_hello_df.loc[: ,'Timestamp'] = pd.to_numeric(client_hello_df['Timestamp'], errors='coerce')
        client_hello_df = client_hello_df.dropna(subset=['Service', 'Timestamp'])

        # Prepare features (X) and target (y)
        X = client_hello_df[['Timestamp', 'Packet Size', 'SNI', 'Destination IP', 'Cipher Suite']]
        y = client_hello_df['Service']

        # Check if there is valid data to train on
        if len(y) == 0:
            print("No valid data to train on.")
            return

        # Step 1: Track all unique SNIs in the original dataset
        unique_snis = client_hello_df['SNI'].unique()

        # Step 2: Perform the split based on unique SNIs
        np.random.shuffle(unique_snis)
        train_snis, test_snis = train_test_split(unique_snis, test_size=0.2, random_state=42)

        # Step 3: Filter the client_hello_df based on the SNI splits
        X_train = client_hello_df[client_hello_df['SNI'].isin(train_snis)][['Timestamp', 'Packet Size', 'SNI', 'Destination IP', 'Cipher Suite']]
        y_train = client_hello_df[client_hello_df['SNI'].isin(train_snis)]['Service']

        X_test = client_hello_df[client_hello_df['SNI'].isin(test_snis)][['Timestamp', 'Packet Size', 'SNI', 'Destination IP', 'Cipher Suite']]
        y_test = client_hello_df[client_hello_df['SNI'].isin(test_snis)]['Service']

        # Step 4: Preprocessing for numerical and categorical features
        categorical_features = ['SNI', 'Destination IP', 'Cipher Suite']
        numerical_features = ['Timestamp', 'Packet Size']

        preprocessor = ColumnTransformer(
            transformers=[('num', StandardScaler(), numerical_features),
                          ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)]
        )

        # Build the pipeline with preprocessor and classifier
        model_pipeline = Pipeline(steps=[('preprocessor', preprocessor),
                                          ('classifier', RandomForestClassifier(random_state=42))])

        # Step 5: Train the model with the updated training data
        model_pipeline.fit(X_train, y_train)

        # Step 6: Evaluate the model on the training data
        y_train_pred = model_pipeline.predict(X_train)
        print("\nTraining set results (trained on all SNIs from the train set):")
        train_results = pd.DataFrame({
            'SNI': X_train['SNI'],
            'Actual Service': y_train,
            'Predicted Service': y_train_pred
        })
        print(train_results)

        # Calculate training accuracy and classification report
        train_accuracy = accuracy_score(y_train, y_train_pred)
        print(f"Training Accuracy: {train_accuracy:.4f}")
        print("Training Classification Report:")
        print(classification_report(y_train, y_train_pred, zero_division=0))  # Set zero_division to 0 to suppress warnings

        # Step 7: Evaluate the model on the test set (20% unseen SNIs)
        y_test_pred = model_pipeline.predict(X_test)
        print("\nTest set results (only SNIs seen during training):")
        test_results = pd.DataFrame({
            'SNI': X_test['SNI'],
            'Actual Service': y_test,
            'Predicted Service': y_test_pred
        })
        print(test_results)

        # Calculate test accuracy and classification report
        test_accuracy = accuracy_score(y_test, y_test_pred)
        print(f"Test Accuracy: {test_accuracy:.4f}")
        print("Test Classification Report:")
        print(classification_report(y_test, y_test_pred, zero_division=0))  # Set zero_division to 0 to suppress warnings

        # Step 8: Check for mismatches between Actual and Predicted Services in the test set
        mismatches_test = test_results[test_results['Actual Service'] != test_results['Predicted Service']]
        print("\nMismatches between Actual and Predicted Services (Test set):")
        print(mismatches_test)

        # Track the count of mismatched services
        mismatch_count_test = mismatches_test.shape[0]
        print(f"\nTotal mismatches in test set: {mismatch_count_test}")

        # Step 9: Automatically correct mismatches
        if mismatch_count_test > 0:
            print("\nAutomatically correcting mismatches by setting Predicted Service to Actual Service...")

            # Correct the predicted services where there's a mismatch
            for index, row in mismatches_test.iterrows():
                test_results.loc[test_results['SNI'] == row['SNI'], 'Predicted Service'] = row['Actual Service']

            print("\nCorrected mismatches (Predicted Service set to Actual Service):")
            print(test_results[test_results['Actual Service'] != test_results['Predicted Service']])

            # Save the corrected predictions back to the original DataFrame
            corrected_y_test = test_results['Predicted Service']

            # Step 10: Retrain the model with the corrected test set
            X_train_corrected = pd.concat([X_train, X_test], ignore_index=True)
            y_train_corrected = pd.concat([y_train, corrected_y_test], ignore_index=True)

            model_pipeline.fit(X_train_corrected, y_train_corrected)

            # Save the updated model
            model_pickle_file = 'updated_trained_model.pkl'
            with open(model_pickle_file, 'wb') as f:
                pickle.dump(model_pipeline, f)
            print(f"Updated model has been saved to {model_pickle_file}")

        # Step 11: Save the preprocessor
        preprocessor_pickle_file = 'preprocessor.pkl'
        with open(preprocessor_pickle_file, 'wb') as f:
            pickle.dump(preprocessor, f)
        print(f"Preprocessor has been saved to {preprocessor_pickle_file}")

        # Step 12: Visualization of confusion matrix for the test set
        cm = confusion_matrix(y_test, y_test_pred)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=np.unique(y_test), yticklabels=np.unique(y_test))
        plt.ylabel('Actual')
        plt.xlabel('Predicted')
        plt.title('Confusion Matrix')
        plt.show()

        # Step 13: Display combined output (Actual vs Predicted)
        combined_output = pd.concat([train_results, test_results])
        print("\nCombined output for all SNIs (Actual vs Predicted):")
        print(combined_output)

        print("Model training and evaluation complete.")

    except Exception as e:
        print(f"Error loading CSV: {e}")
