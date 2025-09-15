import uuid

from flask_login import UserMixin
from sqlalchemy import Boolean, Column, DateTime, select, String, Uuid

from moviedb import db
from moviedb.models.mixins import BasicRepositoryMixin


def normalizar_email(email: str) -> str:
    return email.lower()


class User(db.Model, BasicRepositoryMixin, UserMixin):
    __tablename__ = "usuarios"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nome = Column(String(60), nullable=False)
    email_normalizado = Column(String(180), nullable=False, unique=True, index=True)
    password_hash = Column(String(256), nullable=False)
    ativo = Column(Boolean, nullable=False, default=False)

    @property
    def email(self):
        return self.email_normalizado

    @email.setter
    def email(self, value):
        self.email_normalizado = normalizar_email(value)

    @property
    def is_active(self):
        return self.ativo

    def get_id(self):  # https://flask-login.readthedocs.io/en/latest/#alternative-tokens
        return f"{str(self.id)}|{self.password[-15:]}"

    @property
    def password(self):
        return self.password_hash

    @password.setter
    def password(self, value):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(value)

    @classmethod
    def get_by_email(cls, email: str):
        return db.session.execute(
                select(cls).
                where(User.email_normalizado == normalizar_email(email))
        ).scalar_one_or_none()

    def check_password(self, password) -> bool:
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

    def send_email(self, subject: str,
                         body: str,
                         html: str = None):
        pass
