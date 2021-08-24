
from flask import Flask, render_template, request, url_for, jsonify, abort


app = Flask(__name__)

if __name__ == "__main__":
    app.jinja_env.auto_reload = True
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run(debug=True)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/index', methods=["POST"])
def form():
    email = request.form.get("email")
    empresa = request.form.get("empresa")
    celular = request.form.get("celular")
    return jsonify(sh.append(nombres_completos, email, empresa, celular))

