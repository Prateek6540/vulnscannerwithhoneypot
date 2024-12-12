import os
import re
import pickle
import joblib
import requests
from datetime import datetime
from flask import request
from scipy.sparse import hstack

BLOCKLIST_FILE = 'blocked_ips.txt'

def load_blocklist():
    """Load the blocked IPs from the file."""
    if os.path.exists(BLOCKLIST_FILE):
        with open(BLOCKLIST_FILE, 'r') as f:
            blocked_ips = set(f.read().splitlines())
    else:
        blocked_ips = set()
    return blocked_ips

def save_blocklist(blocked_ips):
    """Save the blocked IPs to the file."""
    with open(BLOCKLIST_FILE, 'w') as f:
        for ip in blocked_ips:
            f.write(f"{ip}\n")

def get_geolocation(ip):
    """Get the location information of the IP address."""
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json')
        data = response.json()
        location = f"{data['city']}, {data['region']}, {data['country']}"
    except Exception:
        location = "Unknown"
    return location

def preprocess(query):
    """Preprocess the input query to extract features for prediction."""
    preprocessed_query = []

    def process(x, pattern):
        r = re.compile(pattern)
        l = r.findall(x)
        return len(l)

    def combined_keywords(x):
        r = re.compile(r'null')
        m = re.compile(r'chr')
        n = re.compile(r'char')
        l = r.findall(x)
        k = m.findall(x)
        j = n.findall(x)
        return len(l) + len(k) + len(j)

    def genuine(x):
        count = 0
        genuine_keys = ['select', 'top', 'order', 'fetch', 'join', 'avg', 'count', 'sum', 'rows']
        for i in x.split():
            if (i in genuine_keys):
                count += 1
        return count

    preprocessed_query.append(process(query, "'"))
    preprocessed_query.append(process(query, '"'))
    preprocessed_query.append(process(query, "[!\"#$%&'()*+,-.\/:;<=>?@[\\]^_`{|}~]"))
    preprocessed_query.append(process(query, '(--)'))
    preprocessed_query.append(process(query, '(\/\*)'))
    preprocessed_query.append(process(query, '\s+'))
    preprocessed_query.append(process(query, "%"))
    preprocessed_query.append(process(query, '\snot\s|\sand\s|\sor\s|\sxor\s|&&|\|\||!'))
    preprocessed_query.append(process(query, "'\+|-|[^\/]\*|\/[^\*]'"))
    preprocessed_query.append(process(query, "null"))
    preprocessed_query.append(process(query, '0[xX][0-9a-fA-F]+\s'))
    preprocessed_query.append(process(query, '[a-zA-Z]'))
    preprocessed_query.append(process(query, '[0-9]'))
    preprocessed_query.append(combined_keywords(query))
    preprocessed_query.append(genuine(query))

    return preprocessed_query
