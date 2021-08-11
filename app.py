
from flask import Flask, render_template, request, url_for, jsonify, abort


app = Flask(__name__)

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=False, port=os.environ.get('PORT', 80))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/index', methods=["POST"])
def form():
    email = request.form.get("email")
    empresa = request.form.get("empresa")
    celular = request.form.get("celular")
    return jsonify(sh.append(nombres_completos, email, empresa, celular))

