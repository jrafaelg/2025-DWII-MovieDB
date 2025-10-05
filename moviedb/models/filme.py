import uuid
from datetime import date

from sqlalchemy import Column, Uuid, String, Integer, Boolean, Text, DECIMAL, Table, ForeignKey, Date
from sqlalchemy.orm import relationship

from moviedb.models.mixins import BasicRepositoryMixin
from moviedb import db


# class Base(DeclarativeBase):
#     pass
#
#
# class FilmeGenero(db.Model):
#     __tablename__ = 'filmes_generos'
#
# # Tabela de associação
# filmes_generos = Table(
#     'filmes_generos',
#     Base.metadata,
#     Column('filme_id', Integer, ForeignKey('filmes.id'), primary_key=True),
#     Column('genero_id', Integer, ForeignKey('generos.id'), primary_key=True)
# )

# class Association(Base):
#     __tablename__ = "association_table"
#     left_id: Mapped[int] = mapped_column(ForeignKey("left_table.id"), primary_key=True)
#     right_id: Mapped[int] = mapped_column(ForeignKey("right_table.id"), primary_key=True)
#     extra_data: Mapped[Optional[str]]
#     child: Mapped["Child"] = relationship()

class Avaliacao(db.Model, BasicRepositoryMixin):
    __tablename__ = 'avaliacoes'

    filme_id = Column(Integer, ForeignKey('filmes.id'), primary_key=True)
    usuario_id = Column(Integer, ForeignKey('usuarios.id'), primary_key=True)
    nota = Column(DECIMAL(1, 2))
    data_avaliacao = Column(Date, default=date.today, server_default="NOW()", nullable=False)
    comentario = Column(Text)
    recomenda = Column(Boolean, nullable=False, default=False)

    # Relacionamentos
    filme = relationship('Filme', back_populates='FilmeAvaliacao')
    usuario = relationship('User', back_populates='FilmeAvaliacao')


class FilmeGenero(db.Model, BasicRepositoryMixin):
    __tablename__ = 'filmes_generos'

    filme_id = Column(Integer, ForeignKey('filmes.id'), primary_key=True)
    genero_id = Column(Integer, ForeignKey('generos.id'), primary_key=True)
    principal = Column(Boolean, nullable=False, default=False)

    # Relacionamentos
    filme = relationship('Filme', back_populates='FilmeGenero')
    genero = relationship('Genero', back_populates='FilmeGenero')


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
    faturamento_lancamento = Column(DECIMAL(12,2), default=0)
    poster_principal = Column(Text, nullable=True, default=None)
    link_trailer = Column(Text, nullable=True, default=None)

    filmes_generos = relationship('FilmeGenero', back_populates='filme')
    generos = relationship('Genero', secondary='filmes_generos', viewonly=True)

    filmes_avaliacoes = relationship('FilmeAvaliacao', back_populates='filme')
    avaliacoes = relationship('Avaliacao', secondary='avaliacoes', viewonly=True)


class Genero(db.Model, BasicRepositoryMixin):
    __tablename__ = 'generos'

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nome = Column(String(250), nullable=False)
    descricao = Column(String(250), nullable=False)
    ativo = Column(Boolean, nullable=False, default=True)

    filmes_generos = relationship('FilmeGenero', back_populates='filme')
    filmes = relationship('Filme', secondary='filmes_generos', viewonly=True)



