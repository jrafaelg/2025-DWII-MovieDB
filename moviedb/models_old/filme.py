import uuid
from datetime import date

from sqlalchemy import Column, Uuid, String, Integer, Boolean, Text, DECIMAL, Table, ForeignKey, Date
from sqlalchemy.orm import relationship

from moviedb.models.mixins import BasicRepositoryMixin
from moviedb import db


class Avaliacao(db.Model, BasicRepositoryMixin):
    __tablename__ = 'avaliacoes'

    filme_id = Column(Uuid(as_uuid=True), ForeignKey('filmes.id'), primary_key=True)
    usuario_id = Column(Uuid(as_uuid=True), ForeignKey('usuarios.id'), primary_key=True)

    nota = Column(DECIMAL(1, 2))
    data_avaliacao = Column(Date, default=date.today, server_default="NOW()", nullable=False)
    comentario = Column(Text)
    recomenda = Column(Boolean, nullable=False, default=False)

    # Relacionamentos
    usuario = relationship('User', back_populates='avaliacoes')
    filme = relationship('Filme', back_populates='avaliacoes')


class FilmeGenero(db.Model, BasicRepositoryMixin):
    __tablename__ = 'filmes_generos'

    filme_id = Column(Uuid(as_uuid=True), ForeignKey('filmes.id'), primary_key=True)
    genero_id = Column(Uuid(as_uuid=True), ForeignKey('generos.id'), primary_key=True)
    principal = Column(Boolean, nullable=False, default=False)

    # Relacionamentos
    filme = relationship('Filme', back_populates='filmes_generos')
    genero = relationship('Genero', back_populates='filmes_generos')


class Filme(db.Model, BasicRepositoryMixin):
    __tablename__ = 'filmes'

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    titulo_original = Column(String(250), nullable=False)
    titulo_nacional = Column(String(250), nullable=False)
    ano_lancamento = Column(Integer(), nullable=False)
    lancado = Column(Boolean, nullable=False)
    duracao = Column(Integer(), nullable=False)
    sinopse = Column(Text)
    orcamento = Column(DECIMAL(12, 2))
    faturamento_lancamento = Column(DECIMAL(12, 2), default=0)
    poster_principal = Column(Text, nullable=True, default=None)
    link_trailer = Column(Text, nullable=True, default=None)

    generos = relationship('Genero', secondary='filmes_generos', back_populates='filmes')
    filmes_generos = relationship('FilmeGenero', back_populates='filme')

    usuarios = relationship('User', secondary='avaliacoes', back_populates='filmes_avaliados')
    avaliacoes = relationship('Avaliacao', back_populates='filme')

    # many-to-many relationship to Ator, bypassing the `Atuacao` class
    # dentro de Ator tem filmes
    atores = relationship('Ator', secondary='atuacoes', back_populates="filmes")
    # association between Filme → Atuacao → Ator
    # dentro de Atuacao tem filme
    atuacoes = relationship('Atuacao', back_populates='filme')

    # many-to-many relationship to Pessoa, bypassing the `Participacao` class
    # dentro de Pessoa tem filmes
    pessoas = relationship("Pessoa", secondary="participacoes", back_populates="filmes")

    # association between Filme → Participacao → Pessoa
    # dentro de Participacao tem filme
    participacoes = relationship("Participacao", back_populates="filme")



class Genero(db.Model, BasicRepositoryMixin):
    __tablename__ = 'generos'

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nome = Column(String(250), nullable=False)
    descricao = Column(String(250), nullable=False)
    principal = Column(Boolean, nullable=False, default=False)

    filmes_generos = relationship('FilmeGenero', back_populates='genero')
    filmes = relationship('Filme', secondary='filmes_generos', back_populates='generos')
