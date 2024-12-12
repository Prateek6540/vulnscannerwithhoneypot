from flask import Flask, render_template, request
import socket
from datetime import datetime
from honeyPot import load_blocklist, save_blocklist, get_geolocation, preprocess
from detector import scan_sql_injection
import pickle
import joblib
from scipy.sparse import hstack
from xss_scanner import xss_scanner  # Import the xss_scanner function

app = Flask(__name__)

# Initialize blocklist
blocked_ips = load_blocklist()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/honeyPot')
def honeyPot():
    return render_template('honeyPot.html')

@app.route('/predict', methods=['POST'])
def predict():
    """Route for prediction where the model checks for SQL injection."""
    global blocked_ips
    hostname = socket.gethostname()
    client_ip = socket.gethostbyname(hostname)

    if client_ip in blocked_ips:
        return render_template('blocked.html')  # Show blocked page if IP is permanently blocked

    to_predict_list = request.form.to_dict()
    query = to_predict_list['query']
    query = query.lower()
    arr = preprocess(query)

    li = [query]
    with open('train_bow', 'rb') as f:
        train_bow = pickle.load(f)
    unigram_bow = train_bow.transform(li)
    combine = hstack((unigram_bow, arr))

    xgboost_model = joblib.load('saved_model.pkl')
    predict = xgboost_model.predict(combine)
    prediction = "Positive" if predict[0] == 0 else "Negative"

    if prediction == "Negative":
        blocked_ips.add(client_ip)
        save_blocklist(blocked_ips)

        location = get_geolocation(client_ip)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        query_length = len(query)

        with open("attack_log.txt", "a") as log_file:
            log_file.write(
                f"{timestamp} | IP: {client_ip} | Location: {location} | Query Length: {query_length} | Prediction: {prediction}\n")

    return render_template('predict.html', prediction=prediction, client_ip=client_ip,
                           location=get_geolocation(client_ip), timestamp=datetime.now())

@app.route('/attack_log')
def attack_log():
    try:
        with open("attack_log.txt", "r") as log_file:
            logs = log_file.readlines()
    except FileNotFoundError:
        logs = ["No attack log available."]
    return render_template('attack_log.html', logs=logs)

@app.route('/sqli', methods=['GET', 'POST'])
def sqli():
    if request.method == 'POST':
        url = request.form['url']
        result = scan_sql_injection(url)

        # Extract results from the result_data dictionary
        logs = result.get("logs", [])
        form_list = result.get("form_list", [])
        sqli_detected = result.get("sqli_detected", [])
        risk_state = result.get("risk_state", [])
        db = result.get("db", [])

        # Pass the results to the HTML template
        return render_template('resultsqli.html', logs=logs, form_list=form_list, sqli_detected=sqli_detected,
                               risk_state=risk_state, db=db)

    return render_template('sqli.html')

@app.route('/xss', methods=['GET', 'POST'])
def xss():
    if request.method == 'POST':
        url = request.form['url']
        logs, forms_found, xss_detected, risk_level, payloads_tried = xss_scanner(url)
        return render_template('xssresult.html', logs=logs, form_list=forms_found,
                               xss_detected=xss_detected, risk_level=risk_level, payloads=payloads_tried)
    return render_template('xss.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
