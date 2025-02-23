import subprocess
from flask import Flask, render_template, request, redirect, url_for, session
import logging

import requests
import json
from google import genai
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import os
import google.oauth2.credentials

# Set the environment variable to disable HTTPS requirement for OAuth 2.0
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

key = 'AIzaSyArOaauX98_TyxaKPMxY6nMW-ycn0cWPVk'

initial_prompt = "You are a helpful assistant. Please provide concise and accurate responses. you are an expert at identifying scams but you cant speak moer than 1 word. just yes or no"

id = 'vynavinvinod09.testnet'

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure logging
logging.basicConfig(level=logging.DEBUG)

def get_response_from_gemini(user_message):
    client = genai.Client(api_key=key)
    response = client.models.generate_content(
        model='gemini-2.0-flash',
        contents=f"{initial_prompt}\n\nUser: {user_message}\nAssistant:"
    )
    return response.text

def get_email_from_near():
    result = subprocess.run(['near', 'view', id, 'get_greeting'], capture_output=True, text=True)
    return result.stdout.strip()

def get_gmail_service():
    creds = None
    if 'credentials' in session:
        creds = google.oauth2.credentials.Credentials(**session['credentials'])
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            session['credentials'] = {
                'token': creds.token,
                'refresh_token': creds.refresh_token,
                'token_uri': creds.token_uri,
                'client_id': creds.client_id,
                'client_secret': creds.client_secret,
                'scopes': creds.scopes
            }
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
            session['credentials'] = {
                'token': creds.token,
                'refresh_token': creds.refresh_token,
                'token_uri': creds.token_uri,
                'client_id': creds.client_id,
                'client_secret': creds.client_secret,
                'scopes': creds.scopes
            }
    service = build('gmail', 'v1', credentials=creds)
    return service

def get_gmail_emails():
    service = get_gmail_service()
    try:
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], maxResults=10).execute()
        messages = results.get('messages', [])
        logging.debug(f"Fetched {len(messages)} messages from Gmail")
        emails = []
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            payload = msg['payload']
            headers = payload['headers']
            subject = next(header['value'] for header in headers if header['name'] == 'Subject')
            from_email = next(header['value'] for header in headers if header['name'] == 'From')
            snippet = msg['snippet']
            emails.append((from_email, 'me', subject, snippet))
        logging.debug(f"Parsed {len(emails)} emails")
        return emails
    except Exception as e:
        logging.error(f"Error fetching emails: {e}")
        return []

@app.route('/')
def index():
    if 'credentials' not in session:
        return redirect(url_for('login'))
    email = get_email_from_near()
    blockchain_emails = []
    try:
        blockchain_emails = [("chain", "me", email.split(' and body is ')[0].replace('Subject is ', ''), email.split(' and body is ')[1])]
    except Exception as e:
        logging.error(f"Error parsing blockchain email: {e}")
    gmail_emails = get_gmail_emails()
    all_emails = blockchain_emails + gmail_emails
    logging.debug(f"Blockchain emails: {blockchain_emails}")
    logging.debug(f"All emails: {all_emails}")

    return render_template('index.html', emails=all_emails, blockchain_emails=blockchain_emails)

@app.route('/compose')
def compose():
    if 'credentials' not in session:
        return redirect(url_for('login'))
    return render_template('compose.html')

@app.route('/send_email', methods=['POST'])
def send_email():
    if 'credentials' not in session:
        return redirect(url_for('login'))
    bot_response = get_response_from_gemini(request.form['body'] + ' Is this email a scam? Please verify and answer with just 1 word. Yes or No. Watch for slightly misspelled links, spelling mistakes, urgency, requests for personal information, and generic greetings.')
    if "yes" in bot_response.lower():
        return "Scam detected. Email not sent."
    subject = request.form['subject']
    body = request.form['body']
    formatted_email = f"Subject is {subject} and body is {str(body)}"
    
    # Properly escape the JSON string
    json_data = json.dumps({"greeting": formatted_email})
    
    # Write the email to the blockchain
    subprocess.run(['near', 'call', id, 'set_greeting', json_data, '--accountId', id])
    
    return redirect(url_for('index'))

@app.route('/login')
def login():
    flow = InstalledAppFlow.from_client_secrets_file(
        'credentials.json', SCOPES)
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session['state']
    flow = InstalledAppFlow.from_client_secrets_file(
        'credentials.json', SCOPES, state=state)
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials
    session['credentials'] = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4679, debug=True)