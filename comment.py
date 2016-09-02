from google.appengine.ext import db


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
        """ return all comments on a given post """
        return Comment.all().filter('post_id =', str(pid)).order('-created')
