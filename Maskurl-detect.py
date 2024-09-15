import requests
from urllib.parse import urlparse

def ShortenURL(original_url):
    """
    Function to shorten the original URL using is.gd service
    """
    response = requests.post(f"https://is.gd/create.php?format=json&url={original_url}")
    if response.status_code == 200:
        try:
            short_url = response.json()['shorturl']
            parsed_short_url = urlparse(short_url)
            return parsed_short_url.netloc + parsed_short_url.path  # Return the domain and path
        except KeyError:
            print("Shortened URL not found in the response.")
            return None
    else:
        print("Failed to shorten URL.")
        return None

def ValidateVirusTotalAPIKey(api_key):
    """
    Function to validate VirusTotal API key by checking authentication
    """
    headers = {
        'x-apikey': api_key
    }
    response = requests.get('https://www.virustotal.com/api/v3/users/current', headers=headers)
    
    return response.status_code == 200

def CheckVirusTotal(api_key, url):
    """
    Function to check URL reputation on VirusTotal using the provided API key
    """
    params = {
        'apikey': api_key,
        'resource': url
    }
    response = requests.get('https://www.virustotal.com/api/v3/urls', params=params)
    
    if response.status_code == 200:
        result = response.json()
        if result.get('data'):
            analysis_stats = result['data']['attributes']['last_analysis_stats']
            if analysis_stats['malicious'] > 0 or analysis_stats['suspicious'] > 0:
                return True  # URL is flagged as malicious or suspicious
    return False  # URL is not flagged

if __name__ == "__main__":
    # Your ASCII art goes here
    banner = r"""
$$\      $$\ $$\ $$\                                         $$\   $$\               
$$ | $\  $$ |\__|$$ |                                        \__|  $$ |              
$$ |$$$\ $$ |$$\ $$ | $$$$$$\   $$$$$$$\ $$\   $$\  $$$$$$\  $$\ $$$$$$\   $$\   $$\ 
$$ $$ $$\$$ |$$ |$$ |$$  __$$\ $$  _____|$$ |  $$ |$$  __$$\ $$ |\_$$  _|  $$ |  $$ |
$$$$  _$$$$ |$$ |$$ |$$$$$$$$ |$$ /      $$ |  $$ |$$ |  \__|$$ |  $$ |    $$ |  $$ |
$$$  / \$$$ |$$ |$$ |$$   ____|$$ |      $$ |  $$ |$$ |      $$ |  $$ |$$\ $$ |  $$ |
$$  /   \$$ |$$ |$$ |\$$$$$$$\ \$$$$$$$\ \$$$$$$  |$$ |      $$ |  \$$$$  |\$$$$$$$ |
\__/     \__|\__|\__| \_______| \_______| \______/ \__|      \__|   \____/  \____$$ |
                                                                           $$\   $$ |
                                                                           \$$$$$$  |
                                                                            \______/                                                                
    """
    print(f"\033[94m {banner}\033[00m")

    original_url = input("Enter the URL to mask: ")
    mask_domain = input("Enter the masking domain: ")
    keywords = input("Enter keywords (use '-' instead of whitespace): ")

    # Step 1: Mask the URL
    masked_url = f"{mask_domain}-{keywords}@{ShortenURL(original_url)}"
    print(f"Masked URL: {masked_url}")

    # Step 2: Check and validate VirusTotal API key
    print("Checking if Url is blacklisted or not")
    user_api_key = input("Enter your VirusTotal API key: ")
    is_valid_api_key = ValidateVirusTotalAPIKey(user_api_key)
    
    if not is_valid_api_key:
        print("Invalid VirusTotal API key. Please provide a valid API key.")
        exit(1)

    # Step 3: Check URL reputation only if the API key is valid
    is_blacklisted = CheckVirusTotal(user_api_key, masked_url)
    
    if is_blacklisted:
        print("\033[91m This URL is flagged as malicious or suspicious on VirusTotal.\033[00m")
    else:
        print("\033[92m This URL is not flagged on VirusTotal (Happy Hacking).\033[00m")
