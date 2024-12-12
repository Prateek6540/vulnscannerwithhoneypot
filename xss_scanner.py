import csv
from urllib.parse import urljoin
from pprint import pprint
from bs4 import BeautifulSoup as bs
import requests
import random

xss_detected = []
payloads_tried = []
scan_logs = []
xss_type = ["Reflected Cross-Site Scripting"]
risk_level = []
forms_found = []


def get_all_forms(url):
    # a simple web scrapping function that returns all forms from the HTML content
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    # This function extracts all possible useful information about an HTML `form`
    details = {}
    # get the form action (target url)
    target = form.attrs.get("action")
    if target:
        action = target.lower()
    else:
        action = "?"

    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def submit_form(form_details, url, value):
    # This will submit the received forms
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data, allow_redirects=True)
    else:
        # GET request
        return requests.get(target_url, params=data, allow_redirects=True)


def xss_scanner(url):
    # it takes in the inputed URL and then runs a function to detect all forms vulnerable and then returns true once all the vulnerable forms have been detected.
    forms = get_all_forms(url)
    log1 = f"[+] Detected {len(forms)} forms on {url}"
    scan_logs.append(log1)
    print(log1)

    if len(forms) == 0:
        log2 = f"[+] XSS Not Successful on {url}"
        risk_level.append("Low")
        scan_logs.append(log2)
        print(log2)

    # returning value
    is_vulnerable = False
    unique_forms = []  # List to store unique forms

    for form in forms:
        form_details = get_form_details(form)

        # Check if the form is already in the unique_forms list
        if form_details not in unique_forms:
            unique_forms.append(form_details)  # Add form if not already added
            print(f"[*] Processing form with action: {form_details['action']}")

            with open("payloads.txt", "r") as p:
                pay = [line.strip() for line in p.readlines()]

            for x in pay:
                payload = random.choice(pay)
                payloads_tried.append(payload)
                response = submit_form(form_details, url, payload)
                response_content = response.content.decode()

                if payload in response_content:
                    log3 = f"[!] XSS Detected on {url}"
                    scan_logs.append(log3)
                    print(log3)

                    forms1 = f"[*] Form details:"
                    forms_found.append(forms1)
                    print(forms1)

                    pprint(form_details)
                    forms2 = form_details
                    forms_found.append(forms2)
                    is_vulnerable = True

                else:
                    log5 = f"[+] XSS Not Successful Through Forms on {url}"
                    scan_logs.append(log5)
                    print(log5)

                if pay.index(x) < len(pay) - 1:
                    log6 = f"[*] Trying Next Payload"
                    print(log6)

    xss_detected.append(is_vulnerable)
    if is_vulnerable:
        risk_level.append("High")
    else:
        risk_level.clear()
        risk_level.append("Low")

    log6 = f"XSS Test Complete"
    scan_logs.append(log6)
    print(log6)

    # Ensure to return the expected values as a tuple
    return scan_logs, forms_found, xss_detected, risk_level, payloads_tried


if __name__ == "__main__":
    xss_scanner("http://testphp.vulnweb.com/listproducts.php?cat=1")
    print(xss_detected, risk_level, scan_logs, xss_type, payloads_tried)
