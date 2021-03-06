import json
import oauth2
import sqlite3
import urlparse
from contextlib import closing
from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash

# configuration
DEBUG = True
configFileName = 'config.json'

app = Flask(__name__)
app.config.from_object(__name__)

config = json.load(open(configFileName))

#utility functions
def connect_db():
	return sqlite3.connect(config['db']['database'])

def init_db():
	with closing(connect_db()) as db:
		with app.open_resource('schema.sql') as f:
			db.cursor().executescript(f.read())
		db.commit()

@app.before_request
def before_request():
	g.db = connect_db()

@app.teardown_request
def teardown_request(exception):
	g.db.close()

@app.route('/')
def show_entries():
	cur = g.db.execute('select title, text from entries order by id desc')
	entries = [dict(title=row[0], text=row[1]) for row in cur.fetchall()]
	return render_template('show_entries.html', entries=entries)

@app.route('/add', methods=['POST'])
def add_entry():
	if not session.get('logged_in'):
		abort(401)
	g.db.execute('insert into entries (title, text) values (?, ?)',
	             [request.form['title'], request.form['text']])
	g.db.commit()
	flash('New entry was successfully posted')
	return redirect(url_for('show_entries'))

@app.route('/login', methods=['GET', 'POST'])
def login():
	error = None
	if request.method == 'POST':
		if request.form['username'] != config['user']['username']:
			error = 'Invalid username'
		elif request.form['password'] != config['user']['password']:
			error = 'Invalid password'
		else:
			session['logged_in'] = True
			flash('You were logged in')
			return redirect(url_for('show_entries'))
	return render_template('login.html', error=error)

@app.route('/login-linkedin')
def getRequestToken():
	consumer = oauth2.Consumer(config['linkedin']['consumer_key'], config['linkedin']['secret_key'])
	client = oauth2.Client(consumer)
	resp, content = client.request(config['linkedin']['request_token_url'], "GET")
	print resp
	print content
	content = dict(urlparse.parse_qsl(content))

	#store oauth token and secret for later use
	session['oauth_token'] = content['oauth_token']
	session['oauth_token_secret'] = content['oauth_token_secret']
	url = "%s?oauth_token=%s" % (content['xoauth_request_auth_url'], content['oauth_token'])
	print "redirecting to "+url
	return redirect(url)

@app.route('/oauth_callback')
def oauthCallback():
	if request.args.get('oauth_token') != session['oauth_token']:
		flash("Invalid oauth_token in callback")
		return redirect(url_for('show_entries'))
        consumer = oauth2.Consumer(config['linkedin']['consumer_key'], config['linkedin']['secret_key'])
	token = oauth2.Token(session['oauth_token'], session['oauth_token_secret'])
	token.set_verifier(request.args.get('oauth_verifier'))
	client = oauth2.Client(consumer, token)

	#get a new token and store it permanently
	print
	print "getting new token from "+config['linkedin']['access_token_url']
	resp, content = client.request(config['linkedin']['access_token_url'])
	print resp
	print content
	content = dict(urlparse.parse_qsl(content))
	token = oauth2.Token(content['oauth_token'], content['oauth_token_secret'])
	client = oauth2.Client(consumer, token)

	#make the actual interesting request
	requestUrl="https://api.linkedin.com/v1/people/~"
	print
	print "making request for data at "+requestUrl
	print client.request(requestUrl)
	return redirect(url_for('show_entries'))

@app.route('/logout')
def logout():
	session.pop('logged_in', None)
	flash('You were logged out')
	return redirect(url_for('show_entries'))

# set the secret key.  keep this really secret:
app.secret_key = 'A0Zr98j/4yX R~XHH!jmN]LWX/,?RT'

if __name__ == '__main__':
	app.run()
