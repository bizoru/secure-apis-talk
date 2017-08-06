from flask import Flask, request, redirect, url_for, session, g, flash, render_template, jsonify
from functools import wraps
from flask import request, Response
from flask_jwt import JWT, jwt_required
from flask_oauth import OAuth
import datetime
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = 'super-secret'
app.config['JWT_EXPIRATION_DELTA'] = datetime.timedelta(seconds=10)

oauth = OAuth()


# Use Twitter as example remote application
twitter = oauth.remote_app('twitter',
    # unless absolute urls are used to make requests, this will be added
    # before all URLs.  This is also true for request_token_url and others.
    base_url='https://api.twitter.com/1/',
    # where flask should look for new request tokens
    request_token_url='https://api.twitter.com/oauth/request_token',
    # where flask should exchange the token with the remote application
    access_token_url='https://api.twitter.com/oauth/access_token',
    # twitter knows two authorizatiom URLs.  /authorize and /authenticate.
    # they mostly work the same, but for sign on /authenticate is
    # expected because this will give the user a slightly different
    # user interface on the twitter side.
    authorize_url='https://api.twitter.com/oauth/authenticate',
    # the consumer keys from the twitter application registry.
    consumer_key=os.getenv('API_CONSUMER_KEY', 'abc123')
    consumer_secret= os.getenv('API_CONSUMER_SECRET','abc123')
)

@twitter.tokengetter
def get_twitter_token(token=None):
    return session.get('twitter_token')

people = [
    { 'name': 'Steven',
      'role': 'developer'
    },
    { 'name': 'Alejandro',
      'role': 'developer'
    }
]

USER_DATA = {
    "steven": "abc123"
}


class User(object):
    def __init__(self, id):
        self.id = id

    def __str__(self):
        return "User(id='%s')" % self.id


def verify(username, password):
    if not (username and password):
        return False
    if USER_DATA.get(username) == password:
        print("It's ok passed")
        return User(id=123)

def identity(payload):
    user_id = payload['identity']
    return {"user_id": user_id}

jwt = JWT(app, verify, identity)

def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    return username == 'admin' and password == 'secret'

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route("/api/jwt", methods=['GET'])
@jwt_required()
def jwt_location():
    return jsonify({'status':'Hi, I am using JWT'})

@app.route('/')
def index():
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('login'))

    access_token = access_token[0]

    return render_template('index.html')


@app.route("/api", methods=['GET'])
@requires_auth
def hello():
    return jsonify({'people':people})

@app.route("/api/free", methods=['GET'])
def free_location():
    return jsonify({'status':'This endpoint is for freeeee  '})

@app.route("/api/pay", methods=['GET'])
def pay_location():
    return jsonify({'status':'This is restricted you need to pay'}), 402

@app.route('/authorized')
@twitter.authorized_handler
def oauth_authorized(resp):
    next_url = request.args.get('next') or url_for('index')
    if resp is None:
        flash(u'You denied the request to sign in.')
        return redirect(next_url)

    access_token = resp['oauth_token']
    session['access_token'] = access_token
    session['screen_name'] = resp['screen_name']

    session['twitter_token'] = (
        resp['oauth_token'],
        resp['oauth_token_secret']
    )

    return redirect(url_for('index'))

@app.route('/login')
def login():
    return twitter.authorize(callback=url_for('oauth_authorized',
        next=request.args.get('next') or request.referrer or None))


@app.route('/logout')
def logout():
    session.pop('screen_name', None)
    flash('You were signed out')
    return redirect(request.referrer or url_for('index'))
