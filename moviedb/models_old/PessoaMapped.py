import uuid

from sqlalchemy import ForeignKey, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from models.mixins import BasicRepositoryMixin
from moviedb import db


class Pessoa(db.Model, BasicRepositoryMixin):
    __tablename__ = "pessoas_table"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    sexo_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sexos_table.id"))
    sexo: Mapped["Sexo"] = relationship(back_populates="pessoa")


class Sexo(db.Model, BasicRepositoryMixin):
    __tablename__ = "sexos_table"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    pessoa: Mapped["Pessoa"] = relationship(back_populates="sexo")


