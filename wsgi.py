from flask import Flask

app = Flask(__name__)

@app.route('/devops-bot/uptime')
def uptime():
    return "The system is up and running!"

if __name__ == "__main__":
    app.run()
