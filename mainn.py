import tkinter as tk
from tkinter import messagebox
import numpy as np
import pickle
import requests
from urllib.parse import urlparse
import ipaddress
import re
import platform
import socket
import whois

def get_device_ip():
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except Exception as e:
        return "Unknown"

def get_os():
    os_name = platform.system()
    os_version = platform.version()
    return f"{os_name} {os_version}"

def get_device_location(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        data = response.json()
        location = f"{data['city']}, {data['region']}, {data['country']}"
        return location
    except Exception as e:
        return "Unknown"

def get_sender_ip_and_location(url):
    try:
        domain = urlparse(url).netloc
        ip_address = socket.gethostbyname(domain)
        location = get_device_location(ip_address)
        return ip_address, location
    except Exception as e:
        return "Unknown", "Unknown"

def get_whois_details(url):
    try:
        domain = urlparse(url).netloc
        whois_info = whois.whois(domain)
        owner = whois_info.get('org', 'Unknown')
        return owner
    except Exception as e:
        return "Unknown"

def identify_phishing_attack(response):
    if response is None:
        return "Unable to determine the attack type"
    
    attack_types = {
        "Credential Harvesting": ["login", "password", "signin", "bank"],
        "Fake Form Submission": ["submit", "form", "survey", "input"],
        "Malicious Downloads": ["download", "install", "exe", "zip"],
        "Email Spoofing": ["email", "mail", "webmail"]
    }

    content = response.text.lower()
    for attack, keywords in attack_types.items():
        if any(keyword in content for keyword in keywords):
            return attack
    return "Unknown"

def get_domain(url):  
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain

def having_ip(url):
    try:
        ipaddress.ip_address(url)
        return 1
    except ValueError:
        return 0

def have_at_sign(url):
    return 1 if "@" in url else 0

def get_length(url):
    return 0 if len(url) < 54 else 1

def get_depth(url):
    s = urlparse(url).path.split('/')
    depth = sum(len(segment) > 0 for segment in s)
    return depth

def redirection(url):
    pos = url.rfind('//')
    return 1 if pos > 6 else 0

def http_domain(url):
    domain = urlparse(url).netloc
    return 1 if 'https' in domain else 0

def tiny_url(url):
    shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                          r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                          r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                          r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                          r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                          r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                          r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                          r"tr\.im|link\.zip\.net"
    return 1 if re.search(shortening_services, url) else 0

def prefix_suffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

def web_traffic(url):
    return 0

def iframe(response):
    if response == "":
        return 1
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0
        else:
            return 1

def mouse_over(response): 
    if response == "":
        return 1
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return 0

def right_click(response):
    if response == "":
        return 1
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 0
        else:
            return 1

def forwarding(response):
    if response == "":
        return 1
    else:
        return 1 if len(response.history) > 2 else 0

def get_http_response(url):
    try:
        response = requests.get(url, timeout=5)
        return response
    except requests.exceptions.RequestException as e:
        return None

def extract_features(url):
    features = []
    
    # Address bar based features
    features.append(having_ip(url))
    features.append(have_at_sign(url))
    features.append(get_length(url))
    features.append(get_depth(url))
    features.append(redirection(url))
    features.append(http_domain(url))
    features.append(tiny_url(url))
    features.append(prefix_suffix(url))

    # Domain based features
    dns = 0
    dns_age = 0
    dns_end = 0
    features.append(dns)
    features.append(dns_age)
    features.append(dns_end)
    features.append(web_traffic(url))
    response = get_http_response(url)

    # HTML & Javascript based features
    if response is not None:
        features.append(iframe(response))
        features.append(mouse_over(response))
        features.append(right_click(response))
        features.append(forwarding(response))
    else:
        # If response is None, set these features to 0 or None
        features.extend([0, 0, 0, 0])

    return features, response

def predict_phishing(features):
    # Load the model
    with open('mlp_model.pkl', 'rb') as file:
        loaded_model = pickle.load(file)

    # Make predictions
    new_data = np.array([features])
    prediction = loaded_model.predict(new_data)

    return prediction

def check_phishing():
    url = entry_url.get()
    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL.")
        return
    
    # Extract features
    features, response = extract_features(url)

    # Make prediction
    prediction = predict_phishing(features)
    
    # Identify type of phishing attack
    attack_type = identify_phishing_attack(response)

    # Get sender IP and location
    sender_ip, sender_location = get_sender_ip_and_location(url)
    
    # Get WHOIS details
    owner_details = get_whois_details(url)

    # Display prediction
    if prediction[0] == 0:
        result_text = "Phishing Alert! This URL is classified as phishing."
    else:
        result_text = "No Phishing Detected. This URL seems safe."
    
    # Display additional details
    info_text = (f"Phishing Attack Type: {attack_type}\n"
                 f"Sender IP Address: {sender_ip}\n"
                 f"Sender Location: {sender_location}\n"
                 f"Owner Details: {owner_details}")

    result_label.config(text=result_text)
    info_label.config(text=info_text)

# Set up the GUI
root = tk.Tk()
root.title("Phishing URL Detector")

tk.Label(root, text="Enter URL:").pack(pady=5)
entry_url = tk.Entry(root, width=50)
entry_url.pack(pady=5)

tk.Button(root, text="Check", command=check_phishing).pack(pady=5)

result_label = tk.Label(root, text="", wraplength=400, justify="left")
result_label.pack(pady=10)

info_label = tk.Label(root, text="", wraplength=400, justify="left")
info_label.pack(pady=10)

root.mainloop()
