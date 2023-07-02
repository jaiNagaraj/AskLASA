# Lab: BLOG-1
import flask as fk
import re
import logging
import sqlite3
from dateutil import tz
from datetime import datetime as dt
import hashlib   #import the python hash function library
import hmac		 #import the hmac library
import random
import string
import profanity

app = fk.Flask(
    __name__,
    static_folder="static"
)







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
	print(h_arr[0])
	if (h_arr[0] == "None"): return 1
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


def write_posts(posts):
  return fk.render_template(
		"posts.html",
		posts=posts
	)

def write_perma_post(permapost):
    return fk.render_template(
		"permapost.html",
		permapost=permapost
	)

def write_new_post(subject, content):
	with get_connection() as con:
		cursor = con.cursor()
		dateInUTC = str(dt.now().strftime("%m/%d/%Y %H:%M:%S"))
		date = to_cst(dateInUTC)
		postInsert = (date,subject,content,"Guest")
		cookie = fk.request.cookies.get('user_id')
		if not (cookie is None): id = check_secure_val(cookie)
		if cookie is None or cookie == "" or (id is None):
			cursor.execute("INSERT INTO posts (create_date,subject,content,user) VALUES (?,?,?,?)", postInsert)
		else:
			users = get_users()
			cookie = cookie.split("|")
			hashval = cookie[1]
			print(hashval)
			for user in users:
				print(user['hashvals'])
				if user['hashvals'] == hashval:
					betterPostInsert = (date,subject,content,user['usernames'])
					break
			cursor.execute("INSERT INTO posts (create_date,subject,content,user) VALUES (?,?,?,?)", postInsert)
		row = cursor.execute("SELECT * FROM posts WHERE create_date = \"" + str(date) + "\"")
		arr = row.fetchall()[0]
		return arr['id']


@app.route('/newpost', methods=["GET", "POST"], strict_slashes=False)
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
			return fk.redirect(fk.url_for('blogHome'))



def get_posts():
	with get_connection() as con:
		cursor = con.cursor()
		s = cursor.execute("SELECT * FROM posts ORDER BY create_date DESC limit 10")
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
    connection = sqlite3.connect("blogbosts.db")
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
	if fk.request.method == 'GET':
		return write_signup()
	else:
		user = fk.request.form["user"]
		password = fk.request.form["pass"]
		verify = fk.request.form["verify"]
		email = fk.request.form["email"]
		userError = ''
		passError = ''
		verifyError = ''
		emailError = ''
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
		if not valid_email(email):
			emailError = 'Please enter a valid email.'
			hasErrors = True

		
		if (hasErrors):
			return write_signup(user, password, verify, email, userError, passError, verifyError, emailError)
		else:
			h = make_pw_hash(user,password)
			with get_connection() as con:
				cursor = con.cursor()
				userInsert = (user,h,email)
				cursor.execute("INSERT INTO users (usernames,hashvals,emails) VALUES (?,?,?)", userInsert)
			res = fk.make_response(fk.redirect(fk.url_for("welcome"), code=302))
			id = str(get_id_by_username(user))
			hashCookie = make_secure_val(id)
			set_user_cookie(res,hashCookie)
			return res

@app.route('/login', methods=["GET", "POST"], strict_slashes=False)
def login():
	if fk.request.method == 'GET':
		cookie = fk.request.cookies.get('user_id')
		if not (cookie is None): id = check_secure_val(cookie)
		if cookie is None or cookie == "" or (id is None):
			return write_login()
		return fk.redirect(fk.url_for("welcome"), code=302)
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
			res = fk.make_response(fk.redirect(fk.url_for("welcome"), code=302))
			id = str(get_id_by_username(user))
			hashCookie = make_secure_val(id)
			set_user_cookie(res,hashCookie)
			return res

@app.route('/welcome', methods=["GET", "POST"])
def welcome():
	cookie = fk.request.cookies.get('user_id')
	id = check_secure_val(cookie)
	if cookie is None or cookie == "" or (id is None):
		return (fk.redirect(fk.url_for("login"), code=302))

	users = get_users()
	for user in users:
		if user['id'] == id:
			username = user['usernames']
			break
	return fk.render_template("welcome.html", username=username)

@app.route('/logout', methods=["GET","POST"], strict_slashes=False)	
def logout():
	res = fk.make_response(fk.redirect(fk.url_for("login"), code=302))
	set_user_cookie(res,"")
	return res


def set_user_cookie(res, val):
	res.set_cookie('user_id',val)


def get_id_by_username(username):
	users = get_users()
	for user in users:
		if user['usernames'] == username:
			return user['id']








##################################### ROOT STUFFS ###########################################
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


@app.route('/blog', methods=['GET','POST'], strict_slashes=False)
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
		cursor.execute("CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY, create_date TEXT, subject TEXT, content TEXT, user TEXT)")
		cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, usernames TEXT, hashvals TEXT, emails TEXT)")
		s = cursor.execute("SELECT * FROM posts ORDER BY create_date DESC limit 10")
		print([x for x in s])
		if method == "GET":
			return(write_posts(get_posts()))




app.run(host='0.0.0.0', port='3000')