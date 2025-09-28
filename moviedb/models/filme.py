import uuid

from sqlalchemy import Column, Uuid, String, Integer, Boolean, Text, DECIMAL

from moviedb.models.mixins import BasicRepositoryMixin
from moviedb import db

class Filme(db .Model, BasicRepositoryMixin):
    __tablename__ = 'filmes'

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    titulo_original = Column(String(250), nullable=False)
    titulo_nacional = Column(String(250), nullable=False)
    ano_lancamento = Column(Integer(), nullable=False)
    lancado = Column(Boolean, nullable=False)
    duracao = Column(Integer(), nullable=False)
    sinopse = Column(Text())
    orcamento = Column(DECIMAL)
    faturamento_lancamento = Column(DECIMAL(precision=2), default=0)
    poster_principal = Column(String(250))
    link_trailer = Column(String(250))