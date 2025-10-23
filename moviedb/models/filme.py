import uuid

from decimal import Decimal
from typing import Optional

from sqlalchemy import Column, Uuid, String, Boolean, Text, DECIMAL
from sqlalchemy.orm import relationship, Mapped, mapped_column

from moviedb.models.mixins import BasicRepositoryMixin, AuditMixin
from moviedb import db


class Filme(db.Model, BasicRepositoryMixin, AuditMixin):
    __tablename__ = 'filmes'

    # id: mixin
    titulo_original: Mapped[str] = mapped_column(String(250))
    titulo_nacional: Mapped[str] = mapped_column(String(250), default=None)
    ano_lancamento: Mapped[Optional[int]] = mapped_column(default=None)
    lancado: Mapped[bool] = mapped_column(default=False, server_default='False')
    duracao: Mapped[Optional[int]] = mapped_column(default=None)
    sinopse: Mapped[Optional[str]] = mapped_column(Text, default=None)
    poster_base64: Mapped[Optional[str]] = mapped_column(Text, default=None)
    poster_mime: Mapped[Optional[str]] = mapped_column(String(32), default=None)
    orcamento: Mapped[Optional[Decimal]] = mapped_column(DECIMAL(10, 2), default=None)
    faturamento_lancamento: Mapped[Optional[Decimal]] = mapped_column(DECIMAL(10, 2), default=None)

    link_trailer: Mapped[Optional[str]] = mapped_column(Text, default=None)

    atuacoes: Mapped[list["Atuacoes"]] = relationship(
        back_populates="filme",
        cascade="all, delete-orphan"
    )

    equipes_tecnicas: Mapped[list["EquipeTecnica"]] = relationship(
        back_populates="filme",
        cascade="all, delete-orphan"
    )

    filmes_generos: Mapped[list["FilmeGenero"]] = relationship(
        back_populates="filmes_generos",
        cascade="all, delete-orphan"
    )

    avaliacoes: Mapped[list["Avaliacao"]] = relationship(back_populates="filme", cascade="all, delete-orphan")


class Genero(db.Model, BasicRepositoryMixin, AuditMixin):
    __tablename__ = 'generos'

    # id: mixin
    nome: Mapped[str] = mapped_column(String(250), unique=True, index=True)
    descricao: Mapped[str] = mapped_column(Text, default=None)
    ativo: Mapped[bool] = mapped_column(default=True, server_default='true')

    filmes_generos: Mapped[list["FilmeGenero"]] = relationship(
        back_populates="generos",
        cascade="all, delete-orphan"
    )


class FuncoesTecnicas(db.Model, BasicRepositoryMixin, AuditMixin):
    __tablename__ = 'funcoes_tecnicas'

    # id: mixin
    nome: Mapped[str] = mapped_column(String(250), default=None, unique=True, index=True)
    descricao: Mapped[str] = mapped_column(Text, default=None)
    ativa: Mapped[bool] = mapped_column(default=True, server_default='true')

    equipes_tecnicas: Mapped[list["EquipeTecnica"]] = relationship(
        back_populates="funcoes_tecnicas",
        cascade="all, delete-orphan"
    )
