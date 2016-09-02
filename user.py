import re
import hashlib
import hmac
import random
from string import ascii_lowercase

from google.appengine.ext import db

SECRET = "thisisreallysecret"


def users_key(group='default'):
    return db.Key.from_path('users', group)


def posts_key(group='default'):
    return db.Key.from_path('posts', group)


def make_salt():
    """ returns a string of 5 random characters """
    salt = []
    s = ""
    for i in range(0, 5):
        salt.append(random.choice(ascii_lowercase))
    return s.join(salt)


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
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
