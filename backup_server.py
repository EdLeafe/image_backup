import datetime
import hashlib
import logging
import keyring
import json
import os
import sqlite3
from subprocess import Popen, PIPE

from flask import Flask
from flask import flash
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
app = Flask(__name__)

import pyrax
import pyrax.utils as utils

DEFAULT_RETENTION = 7

logger = app.logger
handler = logging.FileHandler("/home/ed/projects/image_backup/logs/backup_server.log")
logger.addHandler(handler)
logger.setLevel(logging.INFO)

def cursor():
    conn = sqlite3.connect("reg.db")
    conn.text_factory = str
    return conn.cursor()

# create table users (
#        pkid integer primary key autoincrement,
#        username text,
#        pw text,
#        server_ids text,
#        retain int,
#        salt text,
#        created date)


def _gen_hash(pw, salt):
    hasher = hashlib.sha256()
    hasher.update(salt)
    hasher.update(pw)
    return hasher.hexdigest()


def hash_password(pw):
    salt = os.urandom(77)
    hashed = _gen_hash(pw, salt)
    return hashed, salt


def check_pw(pw, salt, hashed):
    chk = _gen_hash(pw, salt)
    return chk == hashed
    

def logit(msg, method=logger.info):
    tm = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    method("%s - %s" % (tm, msg))


def runproc(cmd):
    logit("runproc called with: %s" % cmd)
    proc = Popen([cmd], shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=True)
    return proc.communicate()


def auth(fnc):
    def wrapped(*args, **kwargs):
        user = session.get("username")
        logit("Got username: %s" % user)
        if not user:
            session["original_request"] = request.url
            logit("Redirecting to %s" % url_for("login"))
            return redirect(url_for("login"))
        return fnc(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        auth_ok = False
        user = request.form["username"]
        pw = request.form["password"]
        crs = cursor()
        # Make sure username is unique - reject if not
        res = crs.execute("select pkid, pw, salt, server_ids, retain "
                "from users where username = ?", (user,))
        recs = res.fetchall()
        if recs:
            pkid, stored_pw, salt, server_ids, retain = recs[0]
            auth_ok = check_pw(pw, salt, stored_pw)
        if not auth_ok:
            flash("Not a valid user/password combination.")
            session["auth_fail"] = True
            return redirect(url_for("login"))
        session.pop("auth_fail", None)
        session["username"] = user
        session["user_id"] = pkid
        session["server_ids"] = json.loads(server_ids)
        session["retain"] = retain
        logit("Redirecting to %s" % url_for("index"))
        return redirect(url_for("index"))
    greet = "Please sign in"
    if "auth_fail" in session:
        greet = """<h3 style="color: red">Not a valid user/password combination.</h3>"""
    page = """
<h3>%s</h3>
<p>Please sign in:</p>
<form action="" method="post">
    <p>Username: <input type="text" name="username"></p>
    <p>Password: <input type="password" name="password"></p>
    <p><input type="submit" value="Login">
</form>
<p>
Don't have an account? <a href="register">Sign up here</a>.
</p>
""" % greet
    return page


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user = request.form.get("username")
        pw = request.form.get("password")
        apikey = request.form.get("apikey")
        crs = cursor()
        # Make sure username is unique - reject if not
        res = crs.execute("select pkid, username, pw from users "
                "where username = ?", (user,))
        recs = res.fetchall()
        if recs:
           url = url_for("register")
           return """
<h3 style="color: red;">That username already exists.</h3>
<a href="%s">Try Again</a>
""" % url
        # Store username and hashed PW
        hashed, salt = hash_password(pw)
        sql = """insert into users (username, pw, salt, server_ids, retain, created)
                values (?, ?, ?, ?, ?, ?)"""
        crs.execute(sql, (user, hashed, salt, "[]", DEFAULT_RETENTION,
                datetime.datetime.now()))
        keyring.set_password("pyrax", user, apikey)
        # Try connecting to Rackspace with creds
        try:
            pyrax.keyring_auth(user)
        except Exception as e:
            keyring.delete_password("pyrax", user)
            return "Auth failed: %s" % e
        # Warn if invalid creds, and give chance to correct.
        # If all good, bring them to listing page.
        crs.connection.commit()
        session["user_id"] = crs.lastrowid
        logit("ROWID: %s" % session["user_id"])
        session["username"] = user
        session["server_ids"] = []
        session["retain"] = DEFAULT_RETENTION
        logit("checking...")
        logit(url_for("index"))
        return redirect(url_for("index"))
    page = """<form method="post">
    <p>Rackspace Cloud Username: <input type="text" name="username"></p>
    <p>Rackspace Cloud API key: <input type="text" name="apikey"></p>
    <p>Backup Site Password: <input type="password" name="password"></p>
    <p><input type="submit" value="Register">
</form>"""
    return page


@app.route("/test")
def test():
    session.pop("username", None)
    session.pop("user_id", None)
    return 'popped'


def store_settings():
    prefix = "include-"
    included = [k for k in request.form.keys()
            if k.startswith(prefix)]
    server_ids = [val.split(prefix)[-1] for val in included]
    session["server_ids"] = server_ids
    session["retain"] = request.form["retain"]
    crs = cursor()
    sql = "update users set server_ids=?, retain=? where pkid=?"
    logit("ID: %s" % session["user_id"])
    crs.execute(sql, (json.dumps(server_ids), session["retain"], session["user_id"]))
    crs.connection.commit()
    return


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        store_settings()
    username = session.get("username")
    user_id = session.get("user_id")
    if not user_id:
        # Necessary because the auth decorator doesn't work with the route decorator.
        return redirect(url_for("login"))
    server_ids = session["server_ids"]
    retain = session["retain"]
    pyrax.keyring_auth(username)
    cs_dfw = pyrax.connect_to_cloudservers("DFW")
    cs_ord = pyrax.connect_to_cloudservers("ORD")
    servers = cs_dfw.servers.list() + cs_ord.servers.list()
    all_imgs = cs_dfw.images.list() + cs_ord.images.list()
    images = [img for img in all_imgs
            if hasattr(img, "server")]
    image_dict = {}
    for server in servers:
        image_dict[server.id] = [img for img in images
                if img.server["id"] == server.id]

    temp_vars = {"servers": servers,
            "image_dict": image_dict,
            "server_ids": server_ids,
            "retain": retain,
            "str_retain": str(retain),
            }
    return render_template("index.html", **temp_vars)
index = auth(index)


if __name__ == "__main__":
    app.secret_key = keyring.get_password("backup", "secret").encode("utf8")
    app.run(debug=True, host="0.0.0.0")
