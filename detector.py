import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import sys


s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

# Initialize a dictionary to hold logs and results
result_data = {
    "logs": [],
    "form_list": [],
    "db": [],
    "sqli_detected": [],
    "risk_state": []
}

def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append(
            {"type": input_type, "name": input_name, "value": input_value})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def is_vulnerable(first, url):
    """ A simple boolean function to determine SQL Injection vulnerability """
    
    if 'mysql' in first.text.lower():
        error_msg = '[!] Injectable MySQL DB detected'
        result_data["logs"].append(error_msg)
        result_data["sqli_detected"].append("True")
        result_data["risk_state"].append("High")
        result_data["db"] = ["MySQL"]
        display_form_html(url)
        return True
    elif 'native client' in first.text.lower():
        error_msg = '[!] Injectable MSSQL DB detected'
        result_data["logs"].append(error_msg)
        result_data["sqli_detected"].append("True")
        result_data["risk_state"].append("High")
        result_data["db"] = ["MSSQL"]
        display_form_html(url)
        return True
    elif 'syntax error' in first.text.lower():
        error_msg = '[!] Injectable PostGRES DB detected'
        result_data["logs"].append(error_msg)
        result_data["db"] = ["PostGRESQL"]
        result_data["risk_state"].append("High")
        result_data["sqli_detected"].append("True")
        display_form_html(url)
        return True
    elif 'ORA' in first.text.lower():
        error_msg = '[!] Injectable Oracle DB detected'
        result_data["logs"].append(error_msg)
        result_data["db"] = ["Oracle DB"]
        result_data["risk_state"].append("High")
        result_data["sqli_detected"].append("True")
        display_form_html(url)
        return True
    elif 'expects' in first.text.lower():
        error_msg = '[!] Injection Successful: DB Unknown'
        result_data["logs"].append(error_msg)
        result_data["sqli_detected"].append("True")
        result_data["risk_state"].append("High")
        result_data["db"] = ["Unknown"]
        display_form_html(url)
        return True
    else:
        error_msg = '[+] Unsuccessful Error-Based Injection'
        error_msg1 = '[+] Endpoint Parameter not Dynamic or Redirect Occured'
        result_data["logs"].append(error_msg)
        result_data["logs"].append(error_msg1)
        result_data["sqli_detected"].append("False")
        result_data["risk_state"].append("Low")
        result_data["db"] = ["Unknown"]
        return False


def display_form_html(url):
    """Fetch and display at least one form's HTML code from the URL"""
    forms = get_all_forms(url)
    if forms:
        form_details = get_form_details(forms[0])  # Pick the first form
        form_html = f"[+] HTML Form for Vulnerable Endpoint:\n{str(forms[0])}"
        result_data["logs"].append(form_html)  # Add the form HTML to the logs
        result_data["form_list"].append(form_details)  # Add form details to form_list


def scan_sql_injection(url):
    # Reset result_data dictionary for each scan
    global result_data
    result_data = {
        "logs": [],
        "form_list": [],
        "db": [],
        "sqli_detected": [],
        "risk_state": []
    }

    for c in f"\'":
        new_url = f'{url}{c}'
        result_data["logs"].append("[+] SQL Injection Started")
        try_log = "[+] Trying " + new_url
        result_data["logs"].append(try_log)
        try:
            res = s.get(new_url)
        except:
            result_data["logs"].append('Unable to crawl URL. Please ensure URL ends with a /')
            return result_data

        if is_vulnerable(res, new_url):
            detected_log = "[!] SQL Injection vulnerability detected, link: " + new_url
            result_data["logs"].append(detected_log)
            return result_data  # Return the result immediately if vulnerability is found

    forms = get_all_forms(url)
    result_data["logs"].append(f"[+] Detected {len(forms)} forms on {url}")
    if len(forms) > 0:
        result_data["logs"].append('[+] Initiating SQL Injection Through Detected Forms')
        for form in forms:
            form_details = get_form_details(form)
            for c in "\"'":
                data = {}
                for input_tag in form_details["inputs"]:
                    if input_tag["value"] or input_tag["type"] == "hidden":
                        try:
                            data[input_tag["name"]] = input_tag["value"] + c
                        except:
                            pass
                    elif input_tag["type"] != "submit":
                        data[input_tag["name"]] = f"test{c}"
                form_url = urljoin(url, form_details["action"])
                if form_details["method"] == "post":
                    res = s.post(form_url, data=data)
                elif form_details["method"] == "get":
                    res = s.get(form_url, params=data)
                if is_vulnerable(res, form_url):
                    form_html = f"[+] HTML Form for Vulnerable Endpoint:\n{str(form)}"
                    result_data["logs"].append(form_html)
                    result_data["form_list"].append(form_details)

    result_data["logs"].append('SQL Injection Test Complete')
    return result_data



if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python detector.py <URL>")
        sys.exit(1)

    url = sys.argv[1]
    result = scan_sql_injection(url)
    
    # Print the results to the console when running the script directly
    print("\n".join(result["logs"]))
    print(json.dumps(result, indent=4))
