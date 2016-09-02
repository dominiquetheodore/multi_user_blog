from google.appengine.ext import db

from like import *
from unlike import *
from comment import *


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
