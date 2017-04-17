import bcrypt
from sqlalchemy import (
    Column,
    Integer,
    Text
)
from .meta import Base


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False, unique=True)
    role = Column(Text, nullable=False)

    password_hash = Column(Text)

    def set_password(self, pw):
        pwhash = bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt())
        self.password_hash = pwhash.decode('utf-8')

    def check_password(self, pw):
        if self.password_hash is not None:
            expected_hash = self.password_hash.encode('utf-8')
            return bcrypt.checkpw(pw.encode('utf-8'), expected_hash)
        return False
