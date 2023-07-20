import flask as fk
import re
import logging
import sqlite3
from dateutil import tz
from datetime import datetime as dt
from zoneinfo import ZoneInfo
import time
import hashlib   #import the python hash function library
import hmac		 #import the hmac library
import random
import string
from better_profanity import profanity
import urllib.parse
from google.oauth2 import id_token
from google.auth.transport import requests

app = fk.Flask(
    __name__,
    static_folder="static"
)
CLIENT_ID = "453928047443-0bbpt77htqnhkau7npn8ikb5sucb3r0k.apps.googleusercontent.com"
G_SUITE_DOMAIN_STUDENTS = "stu.austinisd.org"
G_SUITE_DOMAIN = "austinisd.org"
app.secret_key = b'\x02H\t\xf7\x82\xf2\x96\xa7"f\x12\xb4\x14\x07]\x82'





##################################### ENCRYPTION STUFFS #####################################
#############################################################################################

def hash_str(s):
	SECRET='imsosecret'.encode()
	return hmac.new(SECRET,s.encode(),"md5").hexdigest()

def make_secure_val(s):
    # return string that is a concatenation of s + '|' + hash_str(s)
	return s + "|" + hash_str(s)

def check_secure_val(h):
	h_arr = h.split("|")
	if (len(h_arr) == 1):
		return None
	#print(h_arr[0])
	if (h_arr[0] == "None"): return None
	s = int(h_arr[0])
	hash = h_arr[1]
	# return s if the hash_str(s) equals hash, otherwise return None
	if hash_str(str(s)) == hash:
		return s
	else:
		return None

def make_salt():
	return ''.join(random.choice(string.ascii_lowercase) for i in range(25))

def make_pw_hash(name, pw, salt=None):
	if salt is None:
		newSalt = make_salt()
		return hash_str(name + pw + newSalt) + "|" + newSalt
	else:
		return hash_str(name + pw + salt) + "|" + salt
	

def valid_pw(name,pw,h):
	arr = h.split("|")
	newHash = make_pw_hash(name,pw,arr[1])
	if newHash != h:
		return False
	return True








##################################### BLOG POST STUFFS ######################################
#############################################################################################


def write_posts(posts,forum):
  return fk.render_template(
		forum + ".html",
		posts=posts
	)

def write_perma_post(permapost):
    return fk.render_template(
		"permapost.html",
		permapost=permapost
	)

def write_new_post(content, forum):
	with get_connection() as con:
		cursor = con.cursor()
		cdt = dt.fromtimestamp(time.time(), tz=ZoneInfo("America/Chicago"))
		date = str(cdt.strftime("%m/%d/%Y at %I:%M:%S"))
		cdt = str(cdt)
		postInsert = (cdt,date,content,"Guest")
		cookie = fk.request.cookies.get('user_id')
		if not (cookie is None): id = check_secure_val(cookie)
		if cookie is None or cookie == "" or (id is None):
			cursor.execute("INSERT INTO " + forum + " (create_date,date_formatted,content,user) VALUES (?,?,?,?)", postInsert)
		else:
			users = get_users()
			cookie = cookie.split("|")
			id = cookie[0]
			for user in users:
				if user['id'] == id:
					betterPostInsert = (cdt,date,content,user['usernames'])
					print('WE FOUND IT!!!')
					break
			cursor.execute("INSERT INTO " + forum + " (create_date,date_formatted,content,user) VALUES (?,?,?,?)", betterPostInsert)
		#row = cursor.execute("SELECT * FROM " + forum + " WHERE create_date = \"" + str(date) + "\"")
		#arr = row.fetchall()[0]
		#return arr['id']


"""@app.route('/newpost', methods=["GET", "POST"], strict_slashes=False)
def new_post():
	method = fk.request.method
	if method == 'GET':
		return fk.render_template(
			'newpost.html',
			ph_subject = '',
			ph_content = '',
			ph_error = ""
		)
	else:
		subject = fk.request.form["subject"]
		content = fk.request.form["content"]
		if subject == "" or content == "":
			return fk.render_template(
				'newpost.html',
				ph_subject = subject,
				ph_content = content,
				ph_error = "Please provide both a subject and content."
			)
		else:
			write_new_post(subject,content)
			return fk.redirect(fk.url_for('blogHome'))"""



def get_posts(forum):
	with get_connection() as con:
		cursor = con.cursor()
		s = cursor.execute("SELECT * FROM " + forum + " ORDER BY create_date")
		return s










##################################### USER STUFFS ###########################################
#############################################################################################


def write_signup(user='', password='', verify='', email='', userError='', passError='', verifyError='', emailError=''):
	return fk.render_template("signup.html", user=user, password=password, verify=verify, 			email=email, userError=userError, passError=passError, verifyError=verifyError, 			emailError=emailError)

def write_login(user='', password='', loginError=''):
	return fk.render_template("login.html", user=user, password=password, 				 
    	loginError=loginError)


def dict_factory(cursor, row):
    d = {}
    for index, col in enumerate(cursor.description):
        d[col[0]] = row[index]
    return d


def get_connection():
    connection = sqlite3.connect("database.db")
    connection.row_factory = dict_factory
    return connection

def to_cst(time):
	utc = dt.strptime(time,"%m/%d/%Y %H:%M:%S")
	utc = utc.replace(tzinfo=tz.tzutc())
	cdt = utc.astimezone(tz.gettz("US/Central"))
	return cdt


def get_users():
	with get_connection() as con:
		cursor = con.cursor()
		s = cursor.execute("SELECT * FROM users")
		s = s.fetchall()
		return s

def get_usernames():
	with get_connection() as con:
		cursor = con.cursor()
		s = cursor.execute("SELECT usernames FROM users")
		s = s.fetchall()
		return s

def check_login(user, pw):
	if not valid_user(user, get_usernames()) == "User exists":
		return False

	users = get_users()
	userFound = False
	for u in users:
		if u['usernames'] == user:
			h = u['hashvals']
			userFound = True
			break
	if not userFound:
		return False
	if not valid_pw(user,pw,h):
		return False
	return True

def valid_user(user, usernames):
	try:
		ret = re.search("^[a-zA-z0-9_-]{3,20}$", user).group(0) == user
	except AttributeError:
		ret = False
	if not ret:
		return "Invalid username!"
	else:
		for users in usernames:
			if users['usernames'] == user:
				return "User exists"
		if ret:
			return "We good"
	pass

def valid_pass(password):
	try:
		ret = re.search("^.{3,20}$", password).group(0) == password
	except AttributeError:
		ret = False
	return ret

def valid_email(email):
	try:
		ret = re.search("^\S+@\S+\.\S+$", email).group(0) == email
	except AttributeError:
		if email == '':
			ret = True
		else:
			ret = False
	return ret


@app.route('/signup', methods=["GET", "POST"], strict_slashes=False)
def signup():
	method = fk.request.method
	return fk.render_template('signup.html')
#	if fk.request.method == 'GET':
#		return write_signup()
#	else:
#		user = fk.request.form["user"]
#		password = fk.request.form["pass"]
#		verify = fk.request.form["verify"]
#		email = fk.request.form["email"]
#		userError = ''
#		passError = ''
#		verifyError = ''
#		emailError = ''
#		hasErrors = False
#
#		# Check for invalid input
#		validUser = valid_user(user, get_usernames())
#		if not validUser == "We good":
#			if validUser == "User exists":
#				userError = "Username already taken"
#			else:
#				userError = 'Your username must contain 3-20 characters from this character set: [a-z,A-Z,0-9,_,-]'
#			hasErrors = True
#		if not valid_pass(password):
#			passError = 'Your password must contain 3-20 characters.'
#			hasErrors = True
#		if not password == verify:
#			verifyError = 'Passwords do not match.'
#			hasErrors = True
#		if not valid_email(email):
#			emailError = 'Please enter a valid email.'
#			hasErrors = True
#
#		
#		if (hasErrors):
#			return write_signup(user, password, verify, email, userError, passError, verifyError, emailError)
#		else:
#			h = make_pw_hash(user,password)
#			with get_connection() as con:
#				cursor = con.cursor()
#				userInsert = (user,h,email)
#				cursor.execute("INSERT INTO users (usernames,hashvals,emails) VALUES (?,?,?)", userInsert)
#			res = fk.make_response(fk.redirect(fk.url_for("profile"), code=302))
#			id = str(get_id_by_username(user))
#			hashCookie = make_secure_val(id)
#			set_user_cookie(res,hashCookie)
#			return res

@app.route('/login', methods=["GET", "POST"], strict_slashes=False)
def login():
	if fk.request.method == 'GET':
		cookie = fk.request.cookies.get('user_id')
		if not (cookie is None): id = check_secure_val(cookie)
		if cookie is None or cookie == "" or (id is None):
			return write_login()
		return fk.redirect(fk.url_for("profile"), code=302)
	else:
		user = fk.request.form["user"]
		password = fk.request.form["pass"]
		loginError = ''
		hasErrors = False

		if not check_login(user,password):
			hasErrors = True
			loginError = "Invalid login"
		
		if (hasErrors):
			return write_login(user, password, loginError)
		else:
			res = fk.make_response(fk.redirect(fk.url_for("profile"), code=302))
			id = str(get_id_by_username(user))
			hashCookie = make_secure_val(id)
			set_user_cookie(res,hashCookie)
			return res

@app.route('/auth', methods=["POST"])
def auth():
	method = fk.request.method
	with get_connection() as con:
		cursor = con.cursor()
		cursor.execute("CREATE TABLE IF NOT EXISTS users (id TEXT, usernames TEXT, hashvals TEXT, emails TEXT, names TEXT, pfp TEXT)")
	if method == "POST":
		token = fk.request.get_data()
		user = fk.request.form.get("user",None)
		password = fk.request.form.get("pass",None)
		if user is not None and password is not None:
			loginError = ''
			hasErrors = False
			if not check_login(user,password):
				hasErrors = True
				loginError = "Invalid login"
			
			if (hasErrors):
				return write_login(user, password, loginError)
			else:
				res = fk.make_response(fk.redirect(fk.url_for("profile"), code=302))
				id = str(get_id_by_username(user))
				hashCookie = make_secure_val(id)
				set_user_cookie(res,hashCookie)
				return res
		token2 = token
		token_decoded = token2.decode()
		data = urllib.parse.parse_qs(token_decoded)
		print(token)
		CSRF_TOKEN_POST = data['g_csrf_token'][0]
		CSRF_TOKEN_COOKIE = fk.request.cookies.get('g_csrf_token')
		if not CSRF_TOKEN_COOKIE:
			fk.abort(400, 'No CSRF token in Cookie.')
		if not CSRF_TOKEN_POST:
			fk.abort(400, 'No CSRF token in POST request.')		
		if not CSRF_TOKEN_COOKIE == CSRF_TOKEN_POST:
			fk.abort(400, 'Failed to verify double submit CSRF cookie. No hacking, please!')
		
		# No CSRF attack, yay!
		idinfo = id_token.verify_oauth2_token(data['credential'][0], requests.Request(), CLIENT_ID)
		domain = idinfo.get('hd',None)
		#if domain is None or (domain != G_SUITE_DOMAIN or domain != G_SUITE_DOMAIN_STUDENTS):
		#	return write_login("", "", "Error: non-AISD email address.")
		userID = idinfo['sub']
		email = idinfo['email']
		name = idinfo['given_name'] + " " + idinfo['family_name']
		pfpLink = idinfo['picture']
		print(idinfo.get('hd',"None"))
		print(idinfo['sub'])
		users = get_users()
		userFound = False
		hasUsername = False
		for user in users:
			if user['id'] == idinfo['sub']:
				userFound = True
				if user['usernames'] is not None and user['usernames'] != "":
					hasUsername = True
				break
		if not userFound:
			with get_connection() as con:
				cursor = con.cursor()
				userInsert = (userID,email,name,pfpLink)
				cursor.execute("INSERT INTO users (id,emails,names,pfp) VALUES (?,?,?,?)", userInsert)
		if not hasUsername:
			res = fk.make_response(fk.redirect(fk.url_for("setup"), code=302))
			hashCookie = make_secure_val(userID)
			set_user_cookie(res,hashCookie)
			return res
		res = fk.make_response(fk.redirect(fk.url_for("profile"), code=302))
		hashCookie = make_secure_val(userID)
		set_user_cookie(res,hashCookie)
		return res


@app.route('/setup', methods=["GET", "POST"])
def setup():
	method = fk.request.method
	if method == "GET":
		cookie = fk.request.cookies.get('user_id')
		if not (cookie is None): id = check_secure_val(cookie)
		if cookie is None or cookie == "" or (id is None):
			fk.abort(400,"You are not logged in, so you cannot access that page.")
		else:
			return fk.render_template(
				"setup.html"
			)
	else:
		user = fk.request.form["user"]
		password = fk.request.form["pass"]
		verify = fk.request.form["verify"]
		userError = ''
		passError = ''
		verifyError = ''
		hasErrors = False

		# Check for invalid input
		validUser = valid_user(user, get_usernames())
		if not validUser == "We good":
			if validUser == "User exists":
				userError = "Username already taken"
			else:
				userError = 'Your username must contain 3-20 characters from this character set: [a-z,A-Z,0-9,_,-]'
			hasErrors = True
		if not valid_pass(password):
			passError = 'Your password must contain 3-20 characters.'
			hasErrors = True
		if not password == verify:
			verifyError = 'Passwords do not match.'
			hasErrors = True

		
		if (hasErrors):
			return fk.render_template(
				"setup.html",
				user = user,
				password = password,
				verify = verify,
				userError = userError,
				passError = passError,
				verifyError = verifyError
			)
		else:
			cookie = fk.request.cookies.get('user_id')
			userID = str(check_secure_val(cookie))
			h = make_pw_hash(user,password)
			with get_connection() as con:
				cursor = con.cursor()
				cursor.execute(f"UPDATE users SET usernames = ? WHERE id = '{userID}'", (user,))
				cursor.execute(f"UPDATE users SET hashvals = ? WHERE id = '{userID}'", (h,))
			return fk.make_response(fk.redirect(fk.url_for("profile"), code=302))

@app.route('/profile', methods=["GET", "POST"])
def profile():
	cookie = fk.request.cookies.get('user_id')
	id = check_secure_val(cookie)
	if cookie is None or cookie == "" or (id is None):
		return (fk.redirect(fk.url_for("login"), code=302))

	users = get_users()
	name = ""
	for user in users:
		if str(user['id']) == str(id):
			print('yay!')
			name = user['names']
			username = user['usernames']
			if username is None or username == "":
				return fk.make_response(fk.redirect(fk.url_for("setup"), code=302))
			email = user['emails']
			pfp = user['pfp']
			break
	fk.session['logged_in'] = True
	return fk.render_template(
		"profile.html",
		name=name,
		username=username,
		email=email,
		pfp=pfp
	)

@app.route('/logout', methods=["POST"], strict_slashes=False)	
def logout():
	fk.session['logged_in'] = False
	res = fk.make_response(fk.redirect(fk.url_for("login"), code=302))
	set_user_cookie(res,"")
	return res

@app.route('/changeUsername', methods=["GET","POST"])
def changeUsername():
	method = fk.request.method
	if method == "GET":
		cookie = fk.request.cookies.get('user_id')
		if not (cookie is None): id = check_secure_val(cookie)
		if cookie is None or cookie == "" or (id is None):
			fk.abort(400,"You are not logged in, so you cannot access that page.")
		else:
			return fk.render_template(
				"changeUsername.html"
			)
	else:
		cookie = fk.request.cookies.get('user_id')
		id = check_secure_val(cookie)
		users = get_users()
		for user in users:
			if str(user['id']) == str(id):
				username = user['usernames']
				if username is None or username == "":
					return fk.make_response(fk.redirect(fk.url_for("setup"), code=302))
				break
		
		new = fk.request.form["new"]
		verify = fk.request.form["verify"]
		newError = ''
		verifyError = ''
		hasErrors = False

		# Check for invalid input
		validUser = valid_user(new, get_usernames())
		if not validUser == "We good":
			if validUser == "User exists":
				newError = "Username already taken"
			else:
				newError = 'Your username must contain 3-20 characters from this character set: [a-z,A-Z,0-9,_,-]'
			hasErrors = True
		if username == new:
			newError = "The new username cannot be the same as the old one."
			hasErrors = True
		if not check_login(username,verify):
			verifyError = "Wrong password."
			hasErrors = True

		
		if (hasErrors):
			return fk.render_template(
				"changeUsername.html",
				new = new,
				verify = verify,
				newError = newError,
				verifyError = verifyError
			)
		else:
			cookie = fk.request.cookies.get('user_id')
			userID = str(check_secure_val(cookie))
			with get_connection() as con:
				cursor = con.cursor()
				userTuple = (username,)
				newTuple = (new,)
				h = make_pw_hash(new,verify)
				cursor.execute(f"UPDATE ninth SET user = '{new}' WHERE user = ?",userTuple)
				cursor.execute(f"UPDATE tenth SET user = '{new}' WHERE user = ?",userTuple)
				cursor.execute(f"UPDATE eleventh SET user = '{new}' WHERE user = ?",userTuple)
				cursor.execute(f"UPDATE twelfth SET user = '{new}' WHERE user = ?",userTuple)
				cursor.execute(f"UPDATE users SET usernames = ? WHERE id = '{userID}'", newTuple)
				cursor.execute(f"UPDATE users SET hashvals = ? WHERE id = '{userID}'", (h,))
			return fk.make_response(fk.redirect(fk.url_for("profile"), code=302))

@app.route('/changePassword', methods=["GET","POST"])
def changePassword():
	method = fk.request.method
	if method == "GET":
		cookie = fk.request.cookies.get('user_id')
		if not (cookie is None): id = check_secure_val(cookie)
		if cookie is None or cookie == "" or (id is None):
			fk.abort(400,"You are not logged in, so you cannot access that page.")
		else:
			return fk.render_template(
				"changePassword.html"
			)
	else:
		cookie = fk.request.cookies.get('user_id')
		id = check_secure_val(cookie)
		users = get_users()
		for user in users:
			if str(user['id']) == str(id):
				username = user['usernames']
				if username is None or username == "":
					return fk.make_response(fk.redirect(fk.url_for("setup"), code=302))
				break
		
		old = fk.request.form["old"]
		new = fk.request.form["new"]
		verify = fk.request.form["verify"]
		oldError = ''
		newError = ''
		verifyError = ''
		hasErrors = False

		# Check for invalid input
		if not check_login(username,old):
			oldError = "Wrong password."
			hasErrors = True
		if not valid_pass(new):
			newError = 'Your password must contain 3-20 characters.'
			hasErrors = True
		if old == new:
			newError = 'The new password cannot be the same as the old one.'
			hasErrors = True
		if not new == verify:
			verifyError = 'Passwords do not match.'
			hasErrors = True

		
		if (hasErrors):
			return fk.render_template(
				"changePassword.html",
				old = old,
				new = new,
				verify = verify,
				oldError = oldError,
				newError = newError,
				verifyError = verifyError
			)
		else:
			cookie = fk.request.cookies.get('user_id')
			userID = str(check_secure_val(cookie))
			h = make_pw_hash(username,new)
			with get_connection() as con:
				cursor = con.cursor()
				cursor.execute(f"UPDATE users SET hashvals = ? WHERE id = '{userID}'", (h,))
			return fk.make_response(fk.redirect(fk.url_for("profile"), code=302))

@app.route('/deleteAccount', methods=["POST"])
def deleteAccount():
	# Find account ID and username
	with get_connection() as con:
		cursor = con.cursor()
		cookie = fk.request.cookies.get('user_id')
		id = check_secure_val(cookie)
		users = get_users()
		username = ""
		for user in users:
			if str(user['id']) == str(id):
				username = user['usernames']
				break
		
		# Modify all the posts with the deleted account
		userTuple = (username,)
		cursor.execute("UPDATE ninth SET user = '[Account deleted]' WHERE user = ?",userTuple)
		cursor.execute("UPDATE tenth SET user = '[Account deleted]' WHERE user = ?",userTuple)
		cursor.execute("UPDATE eleventh SET user = '[Account deleted]' WHERE user = ?",userTuple)
		cursor.execute("UPDATE twelfth SET user = '[Account deleted]' WHERE user = ?",userTuple)

		# Delete account
		idTuple = (str(id),)
		cursor.execute("DELETE FROM users WHERE id = ?",idTuple)
		fk.session['logged_in'] = False
		res = fk.make_response(fk.redirect(fk.url_for("root"), code=302))
		set_user_cookie(res,"")
		return res


def set_user_cookie(res, val):
	res.set_cookie('user_id',val)


def get_id_by_username(username):
	users = get_users()
	for user in users:
		if user['usernames'] == username:
			return user['id']








##################################### ROUTING STUFFS ########################################
#############################################################################################


@app.route('/', methods=['GET','POST'])
def root():
	method = fk.request.method
	return fk.render_template('home.html')

@app.route('/about', methods=['GET','POST'])
def about():
	method = fk.request.method
	return fk.render_template('about.html')

@app.route('/faq', methods=['GET','POST'])
def faq():
	method = fk.request.method
	return fk.render_template('faq.html')

@app.route('/privacy', methods=['GET','POST'])
def privacy():
	method = fk.request.method
	return fk.render_template('privacy.html')

@app.route('/ninth', methods=['GET','POST'])
def ninth():
	forum = "ninth"
	method = fk.request.method
	#return fk.render_template(forum + '.html')
	method = fk.request.method
	if method == 'POST':
		content = fk.request.form["content"]
		if content == "":
			with get_connection() as con:
				cursor = con.cursor()
				cursor.execute("CREATE TABLE IF NOT EXISTS " + forum + " (id INTEGER PRIMARY KEY, create_date TEXT, date_formatted TEXT, content TEXT, user TEXT)")
				s = cursor.execute("SELECT * FROM " + forum + " ORDER BY create_date DESC")
				return fk.render_template(
					forum + '.html',
					ph_forum = "/" + forum,
					ph_content = content,
					ph_error = "Please write something.",
					posts = get_posts(forum)
				)
		elif profanity.contains_profanity(content):
			return fk.render_template(
				forum + '.html',
				ph_forum = "/" + forum,
				ph_content = content,
				ph_error = "Foul language detected! Use better words.",
				posts = get_posts(forum)
			)
		else:
			write_new_post(content,forum)
			return fk.redirect(fk.url_for(forum))
	# GET REQUEST
	with get_connection() as con:
		cursor = con.cursor()
		cursor.execute("CREATE TABLE IF NOT EXISTS " + forum + " (id INTEGER PRIMARY KEY, create_date TEXT, date_formatted TEXT, content TEXT, user TEXT)")
		s = cursor.execute("SELECT * FROM " + forum + " ORDER BY create_date DESC")
		print([x for x in s])
		return(write_posts(get_posts(forum), forum))

@app.route('/tenth', methods=['GET','POST'])
def tenth():
	forum = "tenth"
	method = fk.request.method
	#return fk.render_template(forum + '.html')
	method = fk.request.method
	if method == 'POST':
		content = fk.request.form["content"]
		if content == "":
			with get_connection() as con:
				cursor = con.cursor()
				cursor.execute("CREATE TABLE IF NOT EXISTS " + forum + " (id INTEGER PRIMARY KEY, create_date TEXT, date_formatted TEXT, content TEXT, user TEXT)")
				s = cursor.execute("SELECT * FROM " + forum + " ORDER BY create_date DESC")
				return fk.render_template(
					forum + '.html',
					ph_forum = "/" + forum,
					ph_content = content,
					ph_error = "Please write something.",
					posts = get_posts(forum)
				)
		elif profanity.contains_profanity(content):
			return fk.render_template(
				forum + '.html',
				ph_forum = "/" + forum,
				ph_content = content,
				ph_error = "Foul language detected! Use better words.",
				posts = get_posts(forum)
			)
		else:
			write_new_post(content,forum)
			return fk.redirect(fk.url_for(forum))
	# GET REQUEST
	with get_connection() as con:
		cursor = con.cursor()
		cursor.execute("CREATE TABLE IF NOT EXISTS " + forum + " (id INTEGER PRIMARY KEY, create_date TEXT, date_formatted TEXT, content TEXT, user TEXT)")
		s = cursor.execute("SELECT * FROM " + forum + " ORDER BY create_date DESC")
		print([x for x in s])
		return(write_posts(get_posts(forum), forum))

@app.route('/eleventh', methods=['GET','POST'])
def eleventh():
	forum = "eleventh"
	method = fk.request.method
	#return fk.render_template(forum + '.html')
	method = fk.request.method
	if method == 'POST':
		content = fk.request.form["content"]
		if content == "":
			with get_connection() as con:
				cursor = con.cursor()
				cursor.execute("CREATE TABLE IF NOT EXISTS " + forum + " (id INTEGER PRIMARY KEY, create_date TEXT, date_formatted TEXT, content TEXT, user TEXT)")
				s = cursor.execute("SELECT * FROM " + forum + " ORDER BY create_date DESC")
				return fk.render_template(
					forum + '.html',
					ph_forum = "/" + forum,
					ph_content = content,
					ph_error = "Please write something.",
					posts = get_posts(forum)
				)
		elif profanity.contains_profanity(content):
			return fk.render_template(
				forum + '.html',
				ph_forum = "/" + forum,
				ph_content = content,
				ph_error = "Foul language detected! Use better words.",
				posts = get_posts(forum)
			)
		else:
			write_new_post(content,forum)
			return fk.redirect(fk.url_for(forum))
	# GET REQUEST
	with get_connection() as con:
		cursor = con.cursor()
		cursor.execute("CREATE TABLE IF NOT EXISTS " + forum + " (id INTEGER PRIMARY KEY, create_date TEXT, date_formatted TEXT, content TEXT, user TEXT)")
		s = cursor.execute("SELECT * FROM " + forum + " ORDER BY create_date DESC")
		print([x for x in s])
		return(write_posts(get_posts(forum), forum))

@app.route('/twelfth', methods=['GET','POST'])
def twelfth():
	forum = "twelfth"
	method = fk.request.method
	#return fk.render_template(forum + '.html')
	method = fk.request.method
	if method == 'POST':
		content = fk.request.form["content"]
		if content == "":
			with get_connection() as con:
				cursor = con.cursor()
				cursor.execute("CREATE TABLE IF NOT EXISTS " + forum + " (id INTEGER PRIMARY KEY, create_date TEXT, date_formatted TEXT, content TEXT, user TEXT)")
				s = cursor.execute("SELECT * FROM " + forum + " ORDER BY create_date DESC")
				return fk.render_template(
					forum + '.html',
					ph_forum = "/" + forum,
					ph_content = content,
					ph_error = "Please write something.",
					posts = get_posts(forum)
				)
		elif profanity.contains_profanity(content):
			return fk.render_template(
				forum + '.html',
				ph_forum = "/" + forum,
				ph_content = content,
				ph_error = "Foul language detected! Use better words.",
				posts = get_posts(forum)
			)
		else:
			write_new_post(content,forum)
			return fk.redirect(fk.url_for(forum))
	# GET REQUEST
	with get_connection() as con:
		cursor = con.cursor()
		cursor.execute("CREATE TABLE IF NOT EXISTS " + forum + " (id INTEGER PRIMARY KEY, create_date TEXT, date_formatted TEXT, content TEXT, user TEXT)")
		s = cursor.execute("SELECT * FROM " + forum + " ORDER BY create_date DESC")
		print([x for x in s])
		return(write_posts(get_posts(forum), forum))


"""@app.route('/blog', methods=['GET','POST'], strict_slashes=False)
def blogHome():
	method = fk.request.method
	if method == 'POST':
		subject = fk.request.form["subject"]
		content = fk.request.form["content"]
		if subject == "" or content == "":
			return fk.render_template(
				'posts.html',
				ph_subject = subject,
				ph_content = content,
				ph_error = "Please provide both a subject and content."
			)
		else:
			write_new_post(subject,content)
			return fk.redirect(fk.url_for('blogHome'))
	with get_connection() as con:
		cursor = con.cursor()
		cursor.execute("CREATE TABLE IF NOT EXISTS ninth (id INTEGER PRIMARY KEY, create_date TEXT, subject TEXT, content TEXT, user TEXT)")
		cursor.execute("CREATE TABLE IF NOT EXISTS tenth (id INTEGER PRIMARY KEY, create_date TEXT, subject TEXT, content TEXT, user TEXT)")
		cursor.execute("CREATE TABLE IF NOT EXISTS eleventh (id INTEGER PRIMARY KEY, create_date TEXT, subject TEXT, content TEXT, user TEXT)")
		cursor.execute("CREATE TABLE IF NOT EXISTS twelfth (id INTEGER PRIMARY KEY, create_date TEXT, subject TEXT, content TEXT, user TEXT)")
		cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, usernames TEXT, hashvals TEXT, emails TEXT)")
		s = cursor.execute("SELECT * FROM posts ORDER BY create_date DESC limit 10")
		print([x for x in s])
		if method == "GET":
			return(write_posts(get_posts()))"""


##################################### ERROR HANDLING STUFFS #####################################
#################################################################################################

@app.errorhandler(400)
def bad_request(e):
	error_code = 400
	error_msg = ""
	if e.description is not None and e.description != "":
		error_msg = e.description
	else:
		error_msg = 'Bad request :('
	return fk.render_template(
		str(error_code) + ".html",
		error_code = str(error_code) + " Bad Request Error",
		error_msg = error_msg
	), error_code

@app.errorhandler(404)
def not_found(e):
	error_code = 404
	error_msg = 'The webpage you seek is in another castle!'
	return fk.render_template(
		str(error_code) + ".html",
		error_code = str(error_code) + " Not Found Error",
		error_msg = error_msg
	), error_code

@app.errorhandler(405)
def wrong_method(e):
	error_code = 405
	error_msg = 'Wrong method to access this page. Likely due to a page which only accepts POST requests being accessed with a GET request.'
	return fk.render_template(
		str(error_code) + ".html",
		error_code = str(error_code) + " Method Not Allowed",
		error_msg = error_msg
	), error_code

@app.errorhandler(500)
def server_error(e):
	error_code = 500
	error_msg = 'That wasn\'t supposed to happen... looks like the website crashed. Maybe send the developer a note about this bug?'
	return fk.render_template(
		str(error_code) + ".html",
		error_code = str(error_code) + " Internal Service Error",
		error_msg = error_msg
	), error_code




app.run(host='0.0.0.0', port='3000')