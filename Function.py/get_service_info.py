def get_service_info(domain):
    """
    Retrieves the service name based on the SNI (Server Name Indication).
    Uses IPinfo API to resolve domain to IP address and then extracts the organization name.
    """
    try:
        # Resolve domain to IP address
        ip_address = socket.gethostbyname(domain)

        # Call the IPinfo API with the resolved IP address and the token
        response = requests.get(f'https://ipinfo.io/{ip_address}/json?token=725f7d8453f807')

        # Parse the JSON response
        data = response.json()

        # Extract the organization name
        org_name = data.get('org', 'Unknown Organization')

        # Check if the domain is two parts and the second part is 'com'
        if domain.count('.') == 1 and domain.endswith('.com'):
            return domain.rstrip(',')  # Remove trailing comma if present

        # Domain starts with 'www.' and ends with '.com'
        if domain.startswith('www.') and domain.endswith('.com'):
            service_name = domain.split('.')[1]
            return service_name.rstrip(',')  # Remove trailing comma if present

        # Domain starts with 'web.' and ends with '.com'
        if domain.startswith('web.') and domain.endswith('.com'):
            service_name = domain.split('.')[1]  # Extract the second part
            return service_name.rstrip(',')  # Remove trailing comma if present

        # Check for single-word domains ending with .com or .net
        if domain.endswith('.com') or domain.endswith('.net'):
            parts = domain.split('.')
            if len(parts) == 2:  # Only one word before the extension
                return parts[0].rstrip(',')  # Remove trailing comma if present

        # Handling domains ending with '.ai' or '.io'
        if domain.endswith('.ai') or domain.endswith('.io'):
            service_name = '.'.join(domain.split('.')[-2:])  # Extract the last two parts
            service_name = service_name.rstrip(',')  # Remove trailing comma if present

        # For other cases, extract the second word of the organization name
        org_words = org_name.split()
        if len(org_words) > 1:
            return org_words[1].rstrip(',')  # Remove trailing comma if present
        else:
            return org_words[0].rstrip(',')  # Remove trailing comma if present

    except socket.gaierror:
        return 'Invalid domain name'
    except Exception as e:
        return str(e)
