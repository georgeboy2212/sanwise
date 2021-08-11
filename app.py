import os
from flask import Flask, render_template, request, url_for, jsonify, abort
import gspread
from oauth2client.service_account import ServiceAccountCredentials

app = Flask(__name__)

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=False, port=os.environ.get('PORT', 80))

credential = ServiceAccountCredentials.from_json_keyfile_name("credentials.json",
["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/spreadsheets", 
"https://www.googleapis.com/auth/drive.file","https://www.googleapis.com/auth/drive"])
client = gspread.authorize(credential)
gsheet = client.open("Clientes sanwise").sheet1


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/index', methods=["POST"])
def form():
    req = request.get_json()
    row = [req["nombres completos"], req["email"], req["empresa"], req["celular"]]
    gsheet.insert_row(row, 2)
    nombres_completos = request.form.get("nombres_completos")
    email = request.form.get("email")
    empresa = request.form.get("empresa")
    celular = request.form.get("celular")
    return jsonify(gsheet.append(nombres_completos, email, empresa, celular))