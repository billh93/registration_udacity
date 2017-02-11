import os
import re
import hashlib
import logging
from random import choice
from string import ascii_lowercase

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
							   autoescape=True)

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)


def make_salt():
	return ''.join(choice(ascii_lowercase) for i in range(5))


def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s|%s' % (h, salt)


def valid_pw(name, pw, h):
	salt = h.split('|')[1]
	return h == make_pw_hash(name, pw, salt)


class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	salt = db.StringProperty(required = True)
	email = db.StringProperty()


class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
	
	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
	
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))


class MainPage(Handler):
	def valid_username(self, username):
		user_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
		return username and user_re.match(username)
	
	def valid_password(self, password):
		pass_re = re.compile(r"^.{3,20}$")
		return password and pass_re.match(password)
	
	def valid_email(self, email):
		email_re = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
		return not email or email_re.match(email)
	
	def get(self):
		self.render("signup.html")
	
	def post(self):
		have_error = False
		username = self.request.get('username')
		password = self.request.get('password')
		verify = self.request.get('verify')
		email = self.request.get('email')
		
		params = dict(username=username, email=email)
		
		if not self.valid_username(username):
			params['username_error'] = "That's not a valid username."
			have_error = True
		
		if not self.valid_password(password):
			params['password_error'] = "That wasn't a valid password."
			have_error = True
		elif password != verify:
			params['verify_error'] = "Your passwords didn't match."
			have_error = True
		
		if not self.valid_email(email):
			params['email_error'] = "That's not a valid email."
			have_error = True
		
		if have_error:
			self.render('signup.html', **params)
		else:
			check_user = db.GqlQuery("SELECT * FROM User WHERE username='" +
			                         username + "'")
			if check_user.count():
				if username == check_user.get().username:
					params['username_exists_error'] = "Username already exists."
					self.render('signup.html', **params)
			else:
				h = make_pw_hash(username, password)
				user_hash = h.split('|')[0]
				user_salt = h.split('|')[1]
				
				user = User(username=username, password=user_hash,
				            salt=user_salt, email=email)
				user.put()
				
				user_id = user.key().id()
				
				user_info = "%s|%s" % (user_id, user_hash)
				
				self.response.headers['Content-Type'] = 'text/plain'
				self.response.headers.add_header('Set-Cookie', 'user=%s' % user_info)
				self.redirect("/welcome")


class WelcomeHandler(Handler):
	def get(self):
		# welcome page checks cookie id for user_id and hash
		# if user_id and hash match the database they can stay there
		# get username from database to display on welcome page
		# if not redirect them to sign up page
		user_cookie_str = self.request.cookies.get('user')
		user_id_cookie_str = user_cookie_str.split('|')[0]
		user_hash_cookie_str = user_cookie_str.split('|')[1]
		get_username = db.GqlQuery("SELECT * FROM User WHERE ID='" +
		                           user_id_cookie_str + "'")
		if get_username.count():
			if get_username.get().username:
				username_from_db = get_username.get().username
				self.render("welcome.html", username=username_from_db)
		else:
			self.redirect('/signup')


app = webapp2.WSGIApplication([('/signup', MainPage),
							   ('/welcome', WelcomeHandler)], debug=True)

