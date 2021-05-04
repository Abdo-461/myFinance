from flask import Flask, render_template

application = Flask(__name__)

@application.route("/")
def dashboard():
    return render_template('dashboard.html')




if __name__ == '__main__':
    application.run(debug=True)