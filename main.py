#!/usr/bin/env python
from flask import Flask, jsonify, render_template
import checks
app = Flask(__name__)

MX = ['91.121.161.13', 'q.meshwith.me'], ['2001:41d0:1:e20d::1', 'q.meshwith.me']
SELECTOR = 'q'
DKIM_FOLDER = 'dkim'
CHECKS = ['dkim', 'spf']


@app.route("/")
def hello():
    """Don't do anything."""
    return "Hello World!"


@app.route("/<domain>")
def rendercheck(domain):
    """Render a check page that interacts with the /check/ route."""
    return render_template('check.html', domain=domain, checks=CHECKS)


@app.route('/check/<domain>/<check>')
def check(domain, check):
    """Check the specified test for a given domain, returns the result as JSON."""
    if check == "spf":
        return jsonify(checks.check_spf(domain, MX))
    elif check == "dkim":
        return jsonify(checks.check_dkim(domain, SELECTOR, DKIM_FOLDER))
    else:
        return jsonify({"error": "unknown test"})

if __name__ == "__main__":
    app.run(debug=True)
