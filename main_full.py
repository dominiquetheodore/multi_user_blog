import webapp2
import os
import jinja2
import re
import hashlib
import json

import hmac
import random
from string import ascii_lowercase
from google.appengine.ext import db

SECRET = "thisisreallysecret"

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


def make_salt():
    salt = []
    s = ""
    for i in range(0, 5):
        salt.append(random.choice(ascii_lowercase))
    return s.join(salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)


def valid_pw(name, pw, h):
    salt = h.split(",")[1]
    h0 = make_pw_hash(name, pw, salt)
    return h == h0


def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def valid_password(password):
    PASSWORD_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return password and PASSWORD_RE.match(password)


def valid_email(email):
    if email == "":
        return True
    else:
        EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
        return email and EMAIL_RE.match(email)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())


def check_secure_val(secure_val):
    return secure_val


class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.TextProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('username =', name).get()
        return u


class Post(db.Model):
    username = db.StringProperty(required=True)
    subject = db.TextProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    permalink = db.StringProperty()


class Comment(db.Model):
    username = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    post_id = db.StringProperty(required=True)

    @classmethod
    def count(cls, post_id):
        cnt = Comment.all().filter('post_id =', post_id).count()
        return cnt


class Like(db.Model):
    username = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)

    @classmethod
    def by_id(cls, name, post_id):
        u = Like.all().filter('username =', name).filter('post_id =', post_id).get()
        return u

    @classmethod
    def count(cls, post_id):
        cnt = Like.all().filter('post_id =', post_id).count()
        return cnt


class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get('user_cookie')
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_cookie')
        self.user = uid


class Signup(BlogHandler):
    def get(self):
        self.render("signup.html", page_type="login")

    def post(self):
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")
        self.email = self.request.get("email")

        params = dict(username=self.username, email=self.email)
        have_error = False

        u = User.by_name(self.username)
        if u:
            params['error_username'] = "This user already exists"
            have_error = True

        if not valid_username(self.username):
            params['error_username'] = "This is not a valid username"
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "This is not a valid password"
            have_error = True
        else:
            if self.password != self.verify:
                params['error_verify'] = "The passwords do not match"
                have_error = True

        if not valid_email(self.email):
            params['error_email'] = "This is not a valid email"
            have_error = True

        if have_error:
            self.render("signup.html", **params)
        else:
            pw_hash = make_pw_hash(self.username, self.password)
            u = User(username=self.username,
                     password=pw_hash, email=self.email)
            u.put()
            self.response.headers.add_header(
                'Set-Cookie', 'user_cookie=%s|%s' % (
                    str(self.username), str(pw_hash)))
            self.redirect("/blog")


class Blog(BlogHandler):
    def get(self):
        # user_cookie = self.request.cookies.get('user_cookie')
        # if user_cookie:
        #     username = user_cookie.split(":")[0]
        #     pw_hash = user_cookie.split(":")[1]
        #     u = User.by_name(username)
        #     if u.password.split(",")[0] == pw_hash:
        #         posts = db.GqlQuery("SELECT * from Post ORDER BY created DESC")
        #         self.render("home.html", username=username, posts=posts)
        #     else:
        #         self.redirect('/login')
        if self.user:
            self.write('you are okay to get in')
        else:
            self.redirect('/login')


class NewPost(BlogHandler):
    def get(self):
        user_cookie = self.request.cookies.get('user_cookie')
        if user_cookie:
            username = user_cookie.split(":")[0]
            pw_hash = user_cookie.split(":")[1]
            u = User.by_name(username)
            if u.password.split(",")[0] == pw_hash:
                self.render("new.html", username=username)
            else:
                self.redirect('/login')
        else:
            self.redirect('/login')

    def post(self):
        self.username = self.request.get("username")
        self.subject = self.request.get("subject")
        self.content = self.request.get("content")

        if self.subject and self.content:
            p = Post(username=self.username,
                     subject=self.subject, content=self.content)
            p.put()
            p_key = p.key().id()
            p.permalink = str(p_key)
            p.put()
            self.redirect("/blog/%s" % p_key)
        else:
            self.render("new.html", username=self.username,
                        error_msg="both subject and content required")


class Entry(BlogHandler):
    def get(self, post_id):
        user_cookie = self.request.cookies.get('user_cookie')
        if user_cookie:
            username = user_cookie.split(":")[0]
            pw_hash = user_cookie.split(":")[1]
            u = User.by_name(username)
            if u.password.split(",")[0] == pw_hash:
                post = Post.get_by_id(int(post_id))
                comments = db.GqlQuery(
                    "SELECT * from Comment WHERE post_id = '%s' ORDER BY created DESC" % post_id)
                cnt_likes = Like.count(post_id)
                cnt_comments = Comment.count(post_id)
                self.render("post.html", username=username, post=post, comments=comments,
                    votes=str(cnt_likes), num_comments=str(cnt_comments))
            else:
                self.redirect('/login')

    def post(self, post_id):
        user_cookie = self.request.cookies.get('user_cookie')
        username = user_cookie.split(":")[0]
        comment = self.request.get("comment")
        post_id = self.request.get("post_id")
        c = Comment(username=username, comment=comment, post_id=post_id)
        c.put()
        self.redirect("/blog/%s" % post_id)


class HasVoted(BlogHandler):
    def get(self):
        self.write("Vote here")

    def post(self):
        post_id = self.request.get("post_id")
        user_cookie = self.request.cookies.get('user_cookie')
        username = user_cookie.split(":")[0]
        l = Like(username=username, post_id=post_id)
        existing = l.by_id(username, post_id)
        if existing:
            self.response.out.write(json.dumps(
                ({'error': "you have already voted"})))


class Vote(BlogHandler):
    def get(self):
        self.write("Vote here")

    def post(self):
        post_id = self.request.get("post_id")
        user_cookie = self.request.cookies.get('user_cookie')
        username = user_cookie.split(":")[0]
        l = Like(username=username, post_id=post_id)
        existing = l.by_id(username, post_id)
        if not existing:
            l.put()
            self.response.out.write(json.dumps(
                ({'message': "Thanks for your vote."})))
        else:
            self.response.out.write(json.dumps(
                ({'error': "you have already voted"})))


class Login(BlogHandler):
    def get(self):
        self.render("login.html", page_type="login")

    def post(self):
        self.username = self.request.get("username")
        self.password = self.request.get("password")

        self.write('\n')
        u = User.by_name(self.username)
        if u and valid_pw(self.username, self.password, u.password):
            self.response.headers.add_header(
                'Set-Cookie', 'user_cookie=%s:%s' % (
                    str(self.username), str(u.password)))
            self.redirect('/blog')
        else:
            self.render("login.html", error_msg="invalid login")


class Logout(BlogHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_cookie=; Path=/')
        self.redirect('/login')

app = webapp2.WSGIApplication([
    ('/signup', Signup),
    ('/', Blog),
    ('/blog', Blog),
    ('/post', NewPost),
    ('/login', Login),
    ('/logout', Logout),
    ('/vote', Vote),
    ('/has_voted', HasVoted),
    ('/blog/(\d+)', Entry)
], debug=True)
