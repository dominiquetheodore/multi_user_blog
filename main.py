import webapp2
import os
import jinja2
import json

# database classes
from user import *
from comment import *
from post import *
from like import *
from unlike import *

# set up the Jinja environment
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


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

    """ display login page and redirect to the blog if user valid """

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
            self.render(
                "login.html", page_type="login", error_msg="invalid login")


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

        # only authenticated users can post
        if self.user:
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
        else:
            self.write("Please log in to post")


class Entry(BlogHandler):

    """ displays a single post """

    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        if post:
            comments = Comment.by_post(post_id)
            cnt_likes = Like.count(post_id)
            cnt_unlikes = Unlike.count(post_id)
            cnt_comments = Comment.count(post_id)
            params = dict(post=post, comments=comments)
            params['votes'] = str(cnt_likes)
            params['unlikes'] = str(cnt_unlikes)
            params['num_comments'] = str(cnt_comments)
            if self.user:
                has_voted = Post.has_voted(post_id, self.user.name)
                has_unliked = Post.has_unliked(post_id, self.user.name)
                params['username'] = self.user.name
                params['has_voted'] = has_voted
                params['has_unliked'] = has_unliked
                self.render("post.html", **params)
            else:
                self.render("post.html", **params)
        else:
            # post not found
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
                        ({'error': "You have already voted!"},
                            {'has_voted': "You have already voted!"})))
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
        if self.user:
            post_id = self.request.get("post_id")
            subject = self.request.get("subject")
            content = self.request.get("content")

            # only store if subject and content is found
            if subject and content:
                p = Post.by_id(int(post_id))
                p.subject = subject
                p.content = content

                # check if user is authorized to edit this post
                if p.username == self.user.name:
                    p.put()
                    self.response.out.write(json.dumps(
                        ({'message': "Your edit was saved successfully."})))
                else:
                    error_msg = "You are not allowed to edit this post."
                    self.response.out.write(json.dumps(
                        ({'error': error_msg})))
            else:
                self.response.out.write(json.dumps(
                    ({'error': "both subject and content required!"})))
        else:
            self.response.out.write(json.dumps(
                ({'error': "Please login to edit a post"})))


class Delete(BlogHandler):

    """ delete posts given ID """

    def post(self):
        if self.user:
            post_id = self.request.get("post_id")
            p = Post.by_id(int(post_id))
            p.delete()

            # check if the user is authorised to delete the post
            if p.username == self.user.name:
                message = "Your post was deleted successfully."\
                    "Redirecting to the home page..."
                self.response.out.write(json.dumps(
                    ({'message': message})))
            else:
                error_msg = "You are not authorized to delete this post"
                self.response.out.write(json.dumps(
                    ({'error': error_msg})))
        else:
            self.response.out.write(json.dumps(
                ({'error': "Please login to delete a post"})))


class CommentbyID(BlogHandler):

    """ return comment by ID """
    """ no need for authentication """

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
        message = "Your comment was saved successfully. Page will reload..."

        if self.user:
            # ensure comment is not blank
            if comment:
                c = Comment(username=self.user.name,
                            comment=comment, post_id=post_id)
                c.put()
                self.response.out.write(json.dumps(
                    ({'message': message})))
            else:
                self.response.out.write(json.dumps(
                    ({'error': "Comment is required"})))
        else:
            self.response.out.write(json.dumps(
                ({'error': "Please login to post a comment"})))


class EditComment(BlogHandler):

    """ edit comment given ID (post requests only) """

    def post(self):
        # user must be logged on to edit a comment
        if self.user:
            comment_id = self.request.get("comment_id")
            comment = self.request.get("comment")
            if comment:
                c = Comment.by_id(int(comment_id))
                # check if user is authorized to edit the comment
                if c.username == self.user.name:
                    c.comment = comment
                    c.put()
                    message = "Your comment was edited successfully."
                    self.response.out.write(json.dumps(
                        ({'message': message})))
                else:
                    message = "You are not authorized to edit this comment"
                    self.response.out.write(json.dumps(
                        ({'message': message})))
            else:
                self.response.out.write(json.dumps(
                    ({'error': "comment is required!"})))
        else:
            self.response.out.write(json.dumps(
                ({'error': "Please login to edit a comment"})))


class DeleteComment(BlogHandler):

    """ delete comment given ID (post requests only) """

    def post(self):
        # user must be logged on to delete a comment
        if self.user:
            comment_id = self.request.get("comment_id")
            c = Comment.by_id(int(comment_id))

            # check if user is authorized to delete the comment
            if c.username == self.user.name:
                c.delete()
                self.response.out.write(json.dumps(
                    ({'message': "Your comment was deleted successfully..."})))
            else:
                self.response.out.write(json.dumps(
                    ({'error': "You are not allowed to delete this comment"})))
        else:
            self.response.out.write(json.dumps(
                ({'error': "Please login to delete a comment"})))


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
