from google.appengine.ext import db


class Like(db.Model):
    username = db.StringProperty(required=True)
    post_id = db.StringProperty(required=True)

    @classmethod
    def by_id(cls, name, post_id):
        u = Like.all().filter('username =', name).filter(
            'post_id =', post_id).get()
        return u

    @classmethod
    def count(cls, post_id):
        cnt = Like.all().filter('post_id =', post_id).count()
        return cnt
