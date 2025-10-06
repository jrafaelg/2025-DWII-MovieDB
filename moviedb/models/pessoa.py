import uuid

from sqlalchemy import Column, String, Uuid, Date, Text, ForeignKey
from sqlalchemy.orm import relationship

from moviedb.models.mixins import BasicRepositoryMixin
from moviedb import db


class Pessoa(db.Model, BasicRepositoryMixin):
    __tablename__ = 'pessoas'

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nome = Column(String(250), nullable=False)
    nacionalidade = Column(String(60), nullable=False)
    nascimento = Column(Date)
    biografia = Column(Text)
    foto_base64 = Column(Text, nullable=True, default=None)
    avatar_base64 = Column(Text, nullable=True, default=None)

    sexo_id = Column(Uuid(as_uuid=True), ForeignKey('sexos.id'))
    sexo = relationship("Sexo", back_populates="pessoa")

    ator = relationship(
        'Ator',
        back_populates='pessoa',
        uselist=False,
        cascade='all, delete-orphan'
    )

class Ator(db.Model, BasicRepositoryMixin):
    __tablename__ = 'atores'

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nome_artistico = Column(String(250), nullable=False)

    # Chave estrangeira (lado "muitos" do relacionamento)
    pessoa_id = Column(Uuid(as_uuid=True), ForeignKey('pessoas.id'), unique=True, nullable=False)

    # Relacionamento one-to-one
    pessoa = relationship('Pessoa', back_populates='ator')


class Sexo(db.Model, BasicRepositoryMixin):
    __tablename__ = 'sexos'
    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nome = Column(String(30), nullable=False)
    pessoa = relationship("Pessoa", back_populates="sexo")








