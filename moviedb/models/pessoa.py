import uuid

from sqlalchemy import Column, String, Uuid, Date, Text

from moviedb.models.mixins import BasicRepositoryMixin
from moviedb import db


class Pessoa(db.Model, BasicRepositoryMixin):
    __tablename__ = 'pessoas'

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nome = Column(String(60), nullable=False)
    nacionalidade = Column(String(60), nullable=False)
    nascimento = Column(Date)
    biografia = Column(Text)
    poster_principal = Column(Text, nullable=True, default=None)



