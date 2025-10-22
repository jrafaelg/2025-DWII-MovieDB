import uuid
from typing import Optional

from sqlalchemy import ForeignKey, String, UniqueConstraint, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from moviedb import db
from moviedb.models.mixins import BasicRepositoryMixin, AuditMixin


class Atuacoes(db.Model, BasicRepositoryMixin, AuditMixin):
    """
    relacionamento m-n entre atores e filmes correspondendo aos papeis dos atores
    """
    __tablename__ = 'atuacoes'

    filme_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('filmes.id'))
    ator_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('atores.id'))
    personagem: Mapped[str] = mapped_column(String(100), default="as him/herself", server_default="as him/herself")

    filme: Mapped["Filme"] = relationship(back_populates="atuacoes")
    ator: Mapped["Ator"] = relationship(back_populates="atuacoes")

    __table_args__ = (
        UniqueConstraint('filme_id', 'ator_id'),
    )


class EquipeTecnica(db.Model, BasicRepositoryMixin, AuditMixin):
    """
    relacionamento m-n entre pessoas e filmes correspondendo às funções desempenhadas nos filmes
    no diagrama refere-se ao modelo 'participação'
    """
    __tablename__ = 'equipes_tecnicas'

    # id: mixin
    filme_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('filmes.id'))
    pessoa_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('pessoas.id'))
    funcao_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('funcoes_tecnicas.id'))

    filme: Mapped["Filme"] = relationship(back_populates="equipes_tecnicas")
    pessoa: Mapped["Pessoa"] = relationship(back_populates="equipes_tecnicas")
    funcao: Mapped["FuncaoTecnica"] = relationship(back_populates="equipes_tecnicas")


class FilmeGenero(db.Model, BasicRepositoryMixin, AuditMixin):
    """
    relacionamento m-n entre generos e filmes
    """
    __tablename__ = 'filmes_generos'

    # id: mixin
    filme_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('filmes.id'))
    genero_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('generos.id'))

    #
    filme: Mapped["Filme"] = relationship(back_populates="filmes_generos")
    genero: Mapped["Genero"] = relationship(back_populates="filmes_generos")

    __table_args__ = (
        UniqueConstraint('filme_id', 'genero_id'),
    )


class Avaliacao(db.Model, BasicRepositoryMixin, AuditMixin):
    """
    relacionamento m-n entre usuarios e filmes correspondendo às avaliações feitas
    """
    __tablename__ = 'avaliacoes'

    # id: mixin
    filme_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('filmes.id'))
    usuario_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('usuarios.id'))
    nota: Mapped[int] = mapped_column(default=1)
    comentario: Mapped[Optional[str]] = mapped_column(Text, default=None)
    recomenda: Mapped[bool] = mapped_column(default=False, server_default="false")

    filme: Mapped["Filme"] = relationship(back_populates="avaliacoes")
    usuario: Mapped["User"] = relationship(back_populates="avaliacoes")
