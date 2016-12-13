#!/usr/bin/env python
# encoding: utf-8

import flask
import os
app = flask.Flask(__name__)


HTML_CONTENT = """<!doctype html>
<meta charset=utf8><title>Remote</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
<style>
    html, body {
        height: 100%;
        margin: 0;
        display: flex;
        flex-flow: column;
        flex-direction: column;
    }
    div {
        align-content: center;
        text-align: center;

        height: 50%;
        width: 100%;
        margin: 0;
        padding: 10px;
        color: #fff;
        font-family: sans-serif;
        font-size: large;
        font-weight: bold;
    }
    #next {
        background: hsl(200, 50%, 50%);
    }
    #prev {
        background: hsl(100, 50%, 50%);
    }
</style>
<body><div id="next">Next</div><div id="prev">Previous</div>
<script>
    document.getElementById("next").addEventListener("click", function() {
        var request = new XMLHttpRequest();
        request.open("GET","/next");
        request.send();
    }, true);
    document.getElementById("prev").addEventListener("click", function() {
        var request = new XMLHttpRequest();
        request.open("GET","/prev");
        request.send();
    }, true);
</script></body>
"""

@app.route("/")
def index_page():
    return HTML_CONTENT

@app.route("/next")
def next():
    os.system("xdotool key Right")
    return ""

@app.route("/prev")
def prev():
    os.system("xdotool key Left")
    return ""

if __name__ == "__main__":
    app.run("0.0.0.0")
