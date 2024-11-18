import csv
import os
def save_to_csv(client_df, server_df, output_file):
    """
    Save the extracted data to a CSV file with the required format.
    """
    print(f"Saving data to {output_file}...")

    try:
        # Debugging: Check the first few rows of data to see the structure
        print("Client Data Columns:", client_df.columns)
        print("Server Data Columns:", server_df.columns)

        # Open file in write mode
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Write Client Hello Parameters (only the necessary columns)
            client_columns = ['No', 'Timestamp', 'Source IP', 'Destination IP', 'Length', 'Info',
                              'Cipher Suite', 'Random', 'Session ID', 'JA3', 'JA4', 'SNI', 'Service']
            writer.writerow(client_columns)  # Write the Client Hello header

            # Write Client Hello data (filtered to include only the necessary columns)
            client_data_filtered = client_df[client_columns]
            writer.writerows(client_data_filtered.values)

            # Add an empty line between Client Hello and Server Hello
            writer.writerow([])

            # Write Server Hello Parameters (only the necessary columns)
            server_columns = ['No', 'Timestamp', 'Source IP', 'Destination IP', 'Length', 'Info',
                              'Cipher Suite', 'Random', 'Session ID', 'JA3S', 'Service']
            writer.writerow(server_columns)  # Write the Server Hello header

            # Write Server Hello data (filtered to include only the necessary columns)
            server_data_filtered = server_df[server_columns]
            writer.writerows(server_data_filtered.values)

            # Add an empty line between Server Hello and Merged Data
            writer.writerow([])


        print(f"Data successfully saved to {output_file}")
    except Exception as e:
        print(f"Error during saving file: {e}")
        return None

    # Ensure the file was created and check its size
    if os.path.exists(output_file):
        file_size = os.path.getsize(output_file)
        print(f"File saved successfully. Size: {file_size} bytes.")
        if file_size == 0:
            print("Warning: The file is empty!")
        else:
            print("File size looks fine.")
    else:
        print("File was not created.")
