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

# set up the Jinja environment
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


def make_salt():
    """ returns a string of 5 random characters """
    salt = []
    s = ""
    for i in range(0, 5):
        salt.append(random.choice(ascii_lowercase))
    return s.join(salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


def posts_key(group='default'):
    return db.Key.from_path('posts', group)


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


class Post(db.Model):
    username = db.StringProperty(required=True)
    subject = db.TextProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    permalink = db.StringProperty()

    @classmethod
    def by_id(cls, pid):
        return Post.get_by_id(pid)

    @classmethod
    def has_voted(cls, uid, username):
        l = Like(username=username, post_id=str(uid))
        if l.by_id(username, str(uid)):
            return "found"
        else:
            return None

    @classmethod
    def likes(cls, pid):
        return Like.count(str(pid))

    @classmethod
    def unlikes(cls, pid):
        return Unlike.count(str(pid))

    @classmethod
    def comments(cls, pid):
        return Comment.count(str(pid))

    @classmethod
    def has_unliked(cls, uid, username):
        u = Unlike(username=username, post_id=str(uid))
        if u.by_id(username, str(uid)):
            return "found"
        else:
            return None


class Comment(db.Model):
    username = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    post_id = db.StringProperty(required=True)

    @classmethod
    def count(cls, post_id):
        """ return number of comments for a given post_id """
        cnt = Comment.all().filter('post_id =', post_id).count()
        return cnt

    @classmethod
    def by_id(cls, cid):
        return Comment.get_by_id(cid)

    @classmethod
    def by_post(cls, pid):
        print "you are here"
        return Comment.all().filter('post_id =', str(pid)).order('-created')


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


class Unlike(db.Model):
    username = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)

    @classmethod
    def by_id(cls, name, post_id):
        u = Unlike.all().filter('username =', name).filter('post_id =', post_id).get()
        return u

    @classmethod
    def count(cls, post_id):
        cnt = Unlike.all().filter('post_id =', post_id).count()
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
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


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
        # check if user already exists and entries are valid
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

        # redraw the signup page if user input is invalid
        if have_error:
            params['page_type'] = "login"
            self.render("signup.html", **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        u = User.register(self.username, self.password, self.email)
        u.put()
        self.login(u)
        self.redirect('/blog')


class Login(BlogHandler):
    """ display login page and redirect to the blog if valid details are entered """

    def get(self):
        self.render("login.html", page_type="login")

    def post(self):
        self.username = self.request.get("username")
        self.password = self.request.get("password")

        u = User.login(self.username, self.password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            self.render("login.html", page_type="login", error_msg="invalid login")


class Blog(BlogHandler):
    """ displays blog front: pass username if logged in """

    def get(self):
        posts = Post.all().order('-created')
        if self.user:
            self.render("home.html", username=self.user.name, posts=posts)
        else:
            self.render("home.html", posts=posts)


class Logout(BlogHandler):
    """ display logout page """

    def get(self):
        self.logout()
        self.redirect('/login')


class NewPost(BlogHandler):
    """ create a new post """

    def get(self):
        if self.user:
            self.render("new.html", username=self.user.name)
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
    """ displays a single post """

    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        if post:
            comments = Comment.by_post(post_id)
            cnt_likes = Like.count(post_id)
            cnt_unlikes = Unlike.count(post_id)
            cnt_comments = Comment.count(post_id)
            if self.user:
                has_voted = Post.has_voted(post_id, self.user.name)
                has_unliked = Post.has_unliked(post_id, self.user.name)
                self.render("post.html", username=self.user.name, post=post, has_voted=has_voted, has_unliked=has_unliked,
                            comments=comments, votes=str(cnt_likes), unlikes=str(cnt_unlikes), num_comments=str(cnt_comments))
            else:
                self.render("post.html", post=post, comments=comments,
                            votes=str(cnt_likes), unlikes=str(cnt_unlikes), num_comments=str(cnt_comments))
        else:
            self.redirect('/404')


class HasVoted(BlogHandler):
    """ check if user has liked a post """

    def post(self):
        post_id = self.request.get("post_id")
        if self.user:
            if Post.by_id(int(post_id)).username == self.user.name:
                self.response.out.write(json.dumps(
                    ({'error': "You cannot like your own post"})))
            else:
                l = Like(username=self.user.name, post_id=post_id)
                existing = l.by_id(self.user.name, post_id)
                if existing:
                    self.response.out.write(json.dumps(
                        ({'error': "You have already voted!"}, {'has_voted': "You have already voted!"})))
        else:
            self.response.out.write(json.dumps(
                ({'error': "Please log in to vote!"})))


class HasUnliked(BlogHandler):
    """ check if user has downvoted a post """

    def post(self):
        post_id = self.request.get("post_id")
        if self.user:
            u = Unlike(username=self.user.name, post_id=post_id)
            existing = u.by_id(self.user.name, post_id)
            if existing:
                self.response.out.write(json.dumps(
                    ({'error': "you have already unliked"})))
        else:
            self.response.out.write(json.dumps(
                ({'error': "Please log in to vote!"})))


class Vote(BlogHandler):
    """ thumbs up to a post """

    def post(self):
        post_id = self.request.get("post_id")
        # if user is logged in, check whether he is trying to vote on his own
        # post or has already voted.
        if self.user:
            if Post.by_id(int(post_id)).username != self.user.name:
                l = Like(username=self.user.name, post_id=post_id)
                u = Unlike(username=self.user.name, post_id=post_id)
                existing = l.by_id(self.user.name, post_id)
                unliked = u.by_id(self.user.name, post_id)
                if existing:
                    self.response.out.write(json.dumps(
                        ({'error': "you have already voted"})))
                else:
                    if unliked:
                        l.put()
                        unliked.delete()
                        print "liking a previously unliked post"
                        o = {
                            'unliked': 'yes',
                            'message': 'Thank you for your vote!'
                        }
                        self.response.out.write(json.dumps(o))
                    else:
                        l.put()
                        self.response.out.write(json.dumps(
                            ({'message': "Thanks for your vote."})))
            else:
                self.response.out.write(json.dumps(
                    ({'error': "You cannot like your own post"})))
        else:
            self.response.out.write(json.dumps(
                ({'error': "Please log in to vote"})))


class Unlike_post(BlogHandler):
    """ downvote a post """

    def post(self):
        post_id = self.request.get("post_id")
        # if user is logged in, check whether he is trying to vote on his own
        # post or has already voted.
        if self.user:
            if Post.by_id(int(post_id)).username != self.user.name:
                l = Like(username=self.user.name, post_id=post_id)
                u = Unlike(username=self.user.name, post_id=post_id)
                existing = u.by_id(self.user.name, post_id)
                liked = l.by_id(self.user.name, post_id)
                if existing:
                    self.response.out.write(json.dumps(
                        ({'error': "you have already unliked this"})))
                else:
                    if liked:
                        u.put()
                        liked.delete()
                        o = {
                            'liked': 'yes',
                            'message': 'You dont like this!'
                        }
                        self.response.out.write(json.dumps(o))
                    else:
                        u.put()
                        self.response.out.write(json.dumps(
                            ({'message': "You don't like this!"})))
            else:
                self.response.out.write(json.dumps(
                    ({'error': "You can't downvote your own post!"})))
        else:
            self.response.out.write(json.dumps(
                ({'error': "Please log in to vote"})))


class Edit(BlogHandler):
    """ edit a post """

    def post(self):
        post_id = self.request.get("post_id")
        subject = self.request.get("subject")
        content = self.request.get("content")
        # only store if subject and content is found
        if subject and content:
            p = Post.by_id(int(post_id))
            p.subject = subject
            p.content = content
            p.put()
            self.response.out.write(json.dumps(
                ({'message': "Your edit was saved successfully."})))
        else:
            self.response.out.write(json.dumps(
                ({'error': "both subject and content required!"})))


class Delete(BlogHandler):
    """ delete posts given ID """

    def post(self):
        post_id = self.request.get("post_id")
        p = Post.by_id(int(post_id))
        p.delete()
        self.response.out.write(json.dumps(
            ({'message': "Your post was deleted successfully. Redirecting to the home page..."})))


class CommentbyID(BlogHandler):
    """ return comment by ID """

    def post(self):
        comment_id = self.request.get("comment_id")
        c = Comment.by_id(int(comment_id))
        self.response.out.write(json.dumps(
            ({'comment': c.comment})))


class CommentPage(BlogHandler):
    """ add comment given post_id """

    def post(self):
        comment = self.request.get("comment")
        post_id = self.request.get("post_id")

        if comment:
            c = Comment(username=self.user.name,
                        comment=comment, post_id=post_id)
            c.put()
            self.response.out.write(json.dumps(
                ({'message': "Your comment was saved successfully. Page will reload..."})))
        else:
            self.response.out.write(json.dumps(
                ({'error': "Comment is required"})))


class EditComment(BlogHandler):
    """ edit comment given ID (post requests only) """

    def post(self):
        comment_id = self.request.get("comment_id")
        comment = self.request.get("comment")
        if comment:
            c = Comment.by_id(int(comment_id))
            c.comment = comment
            c.put()
            self.response.out.write(json.dumps(
                ({'message': "Your comment was edited successfully."})))
        else:
            self.response.out.write(json.dumps(
                ({'error': "comment is required!"})))


class DeleteComment(BlogHandler):
    """ delete comment given ID (post requests only) """

    def post(self):
        comment_id = self.request.get("comment_id")
        c = Comment.by_id(int(comment_id))
        c.delete()
        self.response.out.write(json.dumps(
            ({'message': "Your comment was deleted successfully..."})))


class NotFound(BlogHandler):
    """" page not found """

    def get(self):
        self.render("404.html")


app = webapp2.WSGIApplication([
    ('', Blog),
    ('/', Blog),
    ('/signup', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/post', NewPost),
    ('/blog', Blog),
    ('/blog/', Blog),
    ('/has_voted', HasVoted),
    ('/has_unliked', HasUnliked),
    ('/vote', Vote),
    ('/blog/(\d+)', Entry),
    ('/editcomment', EditComment),
    ('/commentbyid', CommentbyID),
    ('/edit', Edit),
    ('/404', NotFound),
    ('/delete', Delete),
    ('/unlike', Unlike_post),
    ('/comment', CommentPage),
    ('/delete_comment', DeleteComment)
], debug=True)
