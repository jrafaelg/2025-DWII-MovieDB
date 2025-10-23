import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Column, String, Uuid, Date, Text, ForeignKey, Boolean, DECIMAL, Integer
from sqlalchemy.orm import relationship, Mapped, mapped_column

from moviedb.models.mixins import BasicRepositoryMixin, AuditMixin
from moviedb import db


class Pessoa(db.Model, BasicRepositoryMixin, AuditMixin):
    __tablename__ = 'pessoas'

    # id: mixin
    nome: Mapped[str] = mapped_column(String(200))
    nacionalidade: Mapped[Optional[str]] = mapped_column(String(100), default=None)
    nascimento: Mapped[Optional[datetime]] = mapped_column(Date, default=None)
    biografia: Mapped[Optional[str]] = mapped_column(Text, default=None)
    foto_base64: Mapped[Optional[str]] = mapped_column(Text, default=None)
    avatar_base64: Mapped[Optional[str]] = mapped_column(Text, default=None)
    e_ator: Mapped[bool] = mapped_column(default=False, server_default='false')
    sexo: Mapped[Optional[str]] = mapped_column(String(1), default=None)

    # sexo_id = Column(Uuid(as_uuid=True), ForeignKey('sexos.id'))
    # sexo = relationship("Sexo", back_populates="pessoa")

    equipes_tecnicas: Mapped[list["EquipeTecnica"]] = relationship(
        back_populates="pessoa",
        cascade="all, delete-orphan"
    )

    __mapper_args__ = {
        'polymorphic_on': e_ator,
        'polymorphic_identity': False,
        'with_polymorphic': '*'
    }


class Ator(Pessoa, BasicRepositoryMixin, AuditMixin):
    __tablename__ = 'atores'

    # id: mixin
    id: Mapped[uuid.UUID] = mapped_column(ForeignKey('pessoas.id'), primary_key=True)

    nome_artistico: Mapped[str] = mapped_column(String(200), default=None)

    # relacionamento com atuações, para as participações nos filmes
    atuacoes: Mapped[list["Atuacoes"]] = relationship(back_populates="ator", cascade="all, delete-orphan")
