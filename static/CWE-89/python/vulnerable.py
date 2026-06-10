# CWE-89: SQL Injection
# User-controlled request data is concatenated directly into a SQL query string.
# Vulnerable sink: cursor.execute() with a string-formatted query

import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = '%s'" % user_id
    cursor.execute(query)
    return str(cursor.fetchall())
