def fill_client_service_column(client_data):
    import pandas as pd
    """
    Fill the 'Service' column in the Client Hello data.
    This function uses the 'SNI' column to assign a service.
    """
    # Convert client_data to DataFrame
    client_df = pd.DataFrame(client_data,
                             columns=['No', 'Timestamp', 'Source IP', 'Destination IP', 'Length', 'Info',
                                      'Cipher Suite', 'Random', 'Session ID', 'JA3', 'JA4', 'SNI'])

    # Fill the 'Service' column for Client Hello based on the 'SNI'
    client_df['Service'] = client_df['SNI'].apply(get_service_info)

    return client_df
