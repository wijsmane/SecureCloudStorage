from flask import Flask

app = Flask(__name__)


@app.route("/upload")
def upload_file():
    return "<p>Hello, World!</p>"