"An extremely basic naïve implementation of discourse single sign on"
import os
import hmac
import hashlib
import urllib
import base64
from flask import Flask, session, render_template, redirect, request

APP = Flask(__name__)
APP.secret_key = os.getenv("SECRET_KEY", "")
if APP.secret_key == "":
    print("ERROR: configure a SECRET_KEY!")

SSO_SECRET = os.getenv("SSO_SECRET", "")
if SSO_SECRET == "":
    print("ERROR: configure a SSO_SECRET!")

FIRST_USER = {"name" : "russ",
              "external_id" : "hello456",
              "email" : "russ@tinisles.com",
              "username" : "russruss",
              "require_activation" : "true"
             }

@APP.route("/")
def index():
    "homepage route"
    if 'sso' not in request.args or 'sig' not in request.args:
        return "expecting sso and sig"

    # discourse sends me sso info and a signature
    sso_args = request.args.get('sso')
    sig_args = request.args.get('sig')

    # verify the signature
    sig = hmac.new(SSO_SECRET.encode(),
                   msg=sso_args.encode(),
                   digestmod=hashlib.sha256).hexdigest()
    if sig != sig_args:
        return "I don't like your signature"

    # remember the nonce and the return_sso_url from the sso parameter
    sso_args = base64.b64decode(sso_args)
    session["nonce"] = urllib.parse.parse_qs(sso_args)[b'nonce'][0].decode()
    session["return_sso_url"] = urllib.parse.parse_qs(sso_args)[b'return_sso_url'][0].decode()
    return render_template("main.html", info=FIRST_USER)

@APP.route('/validate', methods=['POST'])
def validate():
    "'validate' the user and redirect back into discourse"
    # add the nonce we recieved from discourse into the user info
    FIRST_USER['nonce'] = session["nonce"]
    # base64 encode the urlencoded version of the user info
    sso = base64.b64encode(urllib.parse.urlencode(FIRST_USER).encode())
    # generate a signature on the urlencoded version of the user info
    sig = hmac.new(SSO_SECRET.encode(),
                   msg=sso,
                   digestmod=hashlib.sha256).hexdigest()

    # return the user sso info an a signature
    payload = urllib.parse.urlencode({
        "sso" : sso,
        "sig" : sig
    })
    url = "{}?{}".format(session["return_sso_url"], payload)
    return redirect(url)
