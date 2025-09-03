from flask import Flask, request, jsonify
from dotenv import load_dotenv
import os
import openai
import random
import re
import logging
import jwt
import datetime

load_dotenv()
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

def get_openai_response(log_content):
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        return None, 'OpenAI API key not set.'
    try:
        client = openai.OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "user", "content": f"Analyze these server logs and provide technical recommendations: {log_content}"}
            ],
            max_tokens=200
        )
        return response.choices[0].message.content, None
    except Exception as e:
        return None, str(e)

@app.route('/analyze-log', methods=['POST'])
def analyze_log():
    # JWT Authorization
    auth_header = request.headers.get('Authorization', None)
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Missing or invalid Authorization header."}), 401
    token = auth_header.split(' ')[1]
    secret = os.getenv('JWT_SECRET', 'mysecret')
    try:
        jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid JWT token."}), 401

    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request."}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file."}), 400
    try:
        log_content = file.read().decode('utf-8')
    except Exception:
        logging.error("Could not read file.")
        return jsonify({"error": "Could not read file."}), 400

    # Regex pattern to match log lines starting with timestamp and containing ERROR
    error_pattern = re.compile(r"^\s*\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.*ERROR.*", re.IGNORECASE)
    error_lines = [line for line in log_content.splitlines() if error_pattern.match(line)]
    logging.info(f"Total ERROR lines found: {len(error_lines)}")
    logging.info(f"ERROR lines: {error_lines}")
    if not error_lines:
        logging.warning("No ERROR messages found in log file.")
        return jsonify({"error": "No ERROR messages found in log file."}), 400

    # Choose one error randomly
    selected_error = random.choice(error_lines)
    logging.info(f"Selected error for analysis: {selected_error}")

    response, error = get_openai_response(selected_error)
    if error:
        logging.error(f"OpenAI API error: {error}")
        return jsonify({"error": error}), 500
    return jsonify({"recommendation": response, "selected_error": selected_error})



# Endpoint to generate JWT token
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    if not username:
        return jsonify({'error': 'Username is required'}), 400
    secret = os.getenv('JWT_SECRET', 'mysecret')

    payload = {
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, secret, algorithm='HS256')
    return jsonify({'token': token})

@app.route('/status', methods=['GET'])
def status():
    return jsonify({'status': 'ON'})

if __name__ == '__main__':
    app.run(debug=True)
