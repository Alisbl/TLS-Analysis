import pickle
from sklearn.pipeline import Pipeline
import pandas as pd
def fill_service_column_with_predicted_data(pcap_file_path, model_pickle_file, output_csv_path):
    try:
        # If no output CSV path is provided, set a default path
        output_csv_path = r'C:\Users\pc\PycharmProjects\pythonProject4\predicted_extracted_pcap_data_packets.csv'

        # Load the updated model (updated_trained_model.pkl)
        with open(model_pickle_file, 'rb') as f:
            pipeline = pickle.load(f)

        # Check if the pipeline is correct and contains the 'preprocessor' step
        if isinstance(pipeline, Pipeline):
            # Access the preprocessor and model from the pipeline
            preprocessor = pipeline.named_steps['preprocessor']
            model = pipeline.named_steps['classifier']  # Assuming the classifier is named 'classifier'
        else:
            raise ValueError("The loaded model is not a valid pipeline.")

        # Load the client data
        client_data = extract_client_packets(pcap_file_path)

        # If client_data is a tuple, extract the first element (assuming the actual data is in the first element)
        if isinstance(client_data, tuple):
            client_data = client_data[0]

        # Convert client_data to DataFrame if it's a list
        if isinstance(client_data, list):
            client_data = pd.DataFrame(client_data)

        # Rename columns of client_data to ensure it has the proper column names
        if client_data.shape[1] == 12:
            client_data.columns = ['No', 'Timestamp', 'Source IP', 'Destination IP', 'Length', 'Info',
                                   'Cipher Suite', 'Random', 'Session ID', 'JA3', 'JA4', 'SNI']
        elif client_data.shape[1] == 13:
            client_data.columns = ['No', 'Timestamp', 'Source IP', 'Destination IP', 'Length', 'Info',
                                   'Cipher Suite', 'Random', 'Session ID', 'JA3', 'JA4', 'SNI', 'Service']
        else:
            raise ValueError(f"Unexpected number of columns in client data: {client_data.shape[1]}")

        # Ensure 'Packet Size' column exists for client data
        if 'Packet Size' not in client_data.columns:
            if 'Length' in client_data.columns:
                client_data.rename(columns={'Length': 'Packet Size'}, inplace=True)
            else:
                raise KeyError("Neither 'Packet Size' nor 'Length' column found in the filtered DataFrame.")

        # Step 1: Rename the 'No' column to 'No-client'
        client_data.rename(columns={'No': 'No-client'}, inplace=True)

        # Step 2: Prepare the features for prediction (excluding 'Service' if it exists)
        features = ['Timestamp', 'Packet Size', 'SNI', 'Destination IP', 'Cipher Suite']

        # Filter out rows that are missing essential feature values
        client_data_filtered = client_data.dropna(subset=features)

        # Step 3: Predict the Service for each row in the client_data_filtered using the updated pipeline
        client_data_filtered['Predicted Service'] = pipeline.predict(client_data_filtered[features])

        # Step 4: Remove duplicates based on 'Destination IP'
        client_data_filtered = client_data_filtered.drop_duplicates(subset='Destination IP', keep='first')

        # Step 5: For Client Hello, keep only the required columns (client data with predicted services)
        client_hello_columns = ['No-client', 'Timestamp', 'Source IP', 'Destination IP', 'Packet Size', 'Info',
                                'Cipher Suite', 'Random', 'Session ID', 'JA3', 'JA4', 'SNI', 'Predicted Service']
        client_data_filtered = client_data_filtered[client_hello_columns]

        # Step 6: Rename client data columns to match the required format
        client_data_filtered.columns = ['No-client', 'Timestamp_client', 'Source IP', 'Destination IP', 'Packet Size_client',
                                        'Info_client', 'Cipher Suite_client', 'Random_client', 'Session ID_client', 'JA3', 'JA4',
                                        'SNI', 'Predicted Service']

        # Extract server data
        server_data = extract_server_packets(pcap_file_path)

        # If server_data is a tuple, extract the first element (assuming the actual data is in the first element)
        if isinstance(server_data, tuple):
            server_data = server_data[0]

        # Convert server_data to DataFrame if it's a list
        if isinstance(server_data, list):
            server_data = pd.DataFrame(server_data)

        # Rename columns of server_data to ensure it has the proper column names
        if server_data.shape[1] == 10:
            server_data.columns = ['No_server', 'Timestamp', 'Source IP', 'Destination IP', 'Length', 'Info',
                                   'Cipher Suite', 'Random', 'Session ID', 'JA3S']
        elif server_data.shape[1] == 11:
            server_data.columns = ['No_server', 'Timestamp', 'Source IP', 'Destination IP', 'Length', 'Info',
                                   'Cipher Suite', 'Random', 'Session ID', 'JA3S', 'Service']
        else:
            raise ValueError(f"Unexpected number of columns in server data: {server_data.shape[1]}")

        # Ensure 'Packet Size' column exists for server data
        if 'Packet Size' not in server_data.columns:
            if 'Length' in server_data.columns:
                server_data.rename(columns={'Length': 'Packet Size'}, inplace=True)
            else:
                raise KeyError("Neither 'Packet Size' nor 'Length' column found in the server data.")

        # Step 7: Add the 'Service' column to the server data and fill it based on client data
        server_data['Service'] = None

        # Step 8: Match Destination IP in client data to Source IP in server data
        for idx, row in server_data.iterrows():
            # Match the Source IP in the server data with the Destination IP in client data
            matching_client_data = client_data_filtered[client_data_filtered['Destination IP'] == row['Source IP']]

            if not matching_client_data.empty:
                # If a match is found, assign the Predicted Service to the server row
                predicted_service = matching_client_data['Predicted Service'].values[0]
                server_data.at[idx, 'Service'] = predicted_service

        # Merge client and server data into one DataFrame as per your requested format
        # Step 9: Combine Client Hello parameters (Row 1) + Client data rows (Rows 2-11)
        client_data_rows = client_data_filtered.values.tolist()

        # Row 1 will be the column headers for Client Hello
        client_hello_headers = ['No-client', 'Timestamp_client', 'Source IP', 'Destination IP', 'Packet Size_client',
                                'Info_client', 'Cipher Suite_client', 'Random_client', 'Session ID_client', 'JA3',
                                'JA4', 'SNI', 'Predicted Service']

        # Create an empty row between client and server data
        empty_row = [''] * len(client_hello_headers)

        # Add Client Hello parameters and Client Data rows
        merged_rows = [client_hello_headers] + client_data_rows + [empty_row]

        # Step 10: Add Server Hello parameters (Row 13) + Server data rows (Rows 14-23)
        server_data_rows = server_data.values.tolist()

        # Row 13 will be the column headers for Server Hello
        server_hello_headers = ['No_server', 'Timestamp', 'Source IP', 'Destination IP', 'Packet Size', 'Info',
                                'Cipher Suite', 'Random', 'Session ID', 'JA3S', 'Service']

        # Add Server Hello parameters and Server Data rows
        merged_rows += [server_hello_headers] + server_data_rows

        # Step 11: Save the merged rows to the CSV file
        df = pd.DataFrame(merged_rows)
        df.to_csv(output_csv_path, index=False, header=False)
        print(f"Processed and merged data saved to {output_csv_path}")

    except Exception as e:
        print(f"Error processing the pcap data: {e}")
