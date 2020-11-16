"""
Model DATABASE
"""
from app import db
ROLE_USER = 0
ROLE_ADMIN = 1


class User(db.Model):
    """
    Table User
    """
    id = db.Column(db.Integer, primary_key=True)
    hash_password = db.Column(db.String(120), index=True)
    email = db.Column(db.String(120), index=True, unique=True)
    role = db.Column(db.SmallInteger, default=ROLE_USER)
    active = db.Column(db.SmallInteger, default=ROLE_ADMIN)
    first_name = db.Column(db.String(30), index=True)
    last_name = db.Column(db.String(120), index=True)

    def __repr__(self):
        return '<User %r>' % self.email
