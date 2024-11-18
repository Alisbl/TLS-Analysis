import pandas as pd
def fill_server_service_column(client_df, server_data, destination_ips_from_server):
    """
    Fill the 'Service' column in the Server Hello data based on the matched Client Hello data.
    This function uses the 'Source IP' from the Server Hello to match it with the 'Destination IP' of Client Hello.
    """
    # Convert server_data to DataFrame
    server_df = pd.DataFrame(server_data,
                             columns=['No', 'Timestamp', 'Source IP', 'Destination IP', 'Length', 'Info',
                                      'Cipher Suite', 'Random', 'Session ID', 'JA3S'])

    # Fill the 'Service' column for Server Hello based on matched 'Destination IP' from Client Hello
    server_df['Service'] = server_df['Source IP'].apply(
        lambda x: client_df[client_df['Destination IP'] == x]['Service'].iloc[0] if not client_df[
            client_df['Destination IP'] == x].empty else 'N/A')

    # Remove Server Hello rows where the 'Source IP' does not match a 'Destination IP' in Client Hello
    server_df_filtered = server_df[server_df['Source IP'].isin(destination_ips_from_server)]

    return server_df_filtered
