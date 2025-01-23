# make sure to choose your path
output_file_path = r'C:\Users\pc\PycharmProjects\pythonProject4\extracted_pcap_data_packets.csv'
model_pickle_file = 'updated_trained_model.pkl'
preprocessor_pickle_file = 'preprocessor.pkl'
def main():
    pcap_file_path = r'C:\Users\pc\Desktop\dataset2.pcapng'

    # Step 1: Extract packets from the PCAP file
    client_data = extract_client_packets(pcap_file_path)
    server_data, destination_ips_from_server = extract_server_packets(pcap_file_path)

    # Step 2: Fill the 'Service' column for both Client and Server Hello
    client_df = fill_client_service_column(client_data)
    server_df = fill_server_service_column(client_df, server_data, destination_ips_from_server)

    # Step 3: Save the extracted data to a CSV file
    save_to_csv(client_df, server_df, output_file_path)
    #step 4: train and test the model
    train_and_test_model(output_file_path)
    #step 5:fill the service column using the trained model
    fill_service_column_with_predicted_data(pcap_file_path, model_pickle_file, output_file_path)
    analyzed_data_path = "predicted_extracted_pcap_data_packets.csv"
    if os.path.exists(analyzed_data_path):
        try:
            analyzed_data_df = pd.read_csv(analyzed_data_path)
            results = statistical_analysis(pcap_file_path, analyzed_data_df)
            print("Statistical Analysis Results:")
            for key, value in results.items():
                print(f"{key}: {value}")
        except Exception as e:
            print(f"Error loading or analyzing data: {e}")
    else:
        print("Analyzed data file not found.")

    print(json.dumps(results, indent=4))
if __name__ == '__main__':
    main()
