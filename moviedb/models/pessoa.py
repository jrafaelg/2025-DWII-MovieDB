import uuid

from sqlalchemy import Column, String, Uuid, Date, Text, ForeignKey, Boolean, DECIMAL, Integer
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

    # many-to-many relationship to Filme, bypassing the `Participacao` class
    # dentro de Filme tem participacoes
    filmes = relationship('Filme', secondary='participacoes', back_populates="pessoas")

    # association between Ator → Participacao → Filme
    # dentro de Participacao tem pessoa
    participacoes = relationship('Participacao', back_populates='pessoa')


class Ator(db.Model, BasicRepositoryMixin):
    __tablename__ = 'atores'

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nome_artistico = Column(String(250), nullable=False)

    # Chave estrangeira (lado "muitos" do relacionamento)
    pessoa_id = Column(Uuid(as_uuid=True), ForeignKey('pessoas.id'), unique=True, nullable=False)

    # Relacionamento one-to-one
    pessoa = relationship('Pessoa', back_populates='ator')

    # many-to-many relationship to Filme, bypassing the `Atuacao` class
    # dentro de Filme tem atores
    filmes = relationship('Filme', secondary='atuacoes', back_populates="atores")
    # association between Ator → Atuacao → Filme
    # dentro de Atuacao tem ator
    atuacoes = relationship('Atuacao', back_populates='ator')


class Sexo(db.Model, BasicRepositoryMixin):
    __tablename__ = 'sexos'
    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nome = Column(String(30), nullable=False)
    pessoa = relationship("Pessoa", back_populates="sexo")


class Atuacao(db.Model, BasicRepositoryMixin):
    """
    Tabela associativa entre ator e filme
    Many-to-Many
    """

    __tablename__ = 'atuacoes'

    """
    chave primária composta entre filme_id e ator_id
    """
    filme_id = Column(Uuid(as_uuid=True), ForeignKey('filmes.id'), primary_key=True)
    ator_id = Column(Uuid(as_uuid=True), ForeignKey('atores.id'), primary_key=True)

    papel = Column(String(250), nullable=False)
    protagonista = Column(Boolean, nullable=False, default=False)
    orcamento = Column(DECIMAL(12, 2))
    tempo_tela = Column(Integer, default=0)

    # association between Atuacao → Ator
    ator = relationship('Ator', back_populates='atuacoes')
    # association between Atuacao → Filme
    filme = relationship('Filme', back_populates='atuacoes')


class Participacao(db.Model, BasicRepositoryMixin):
    __tablename__ = 'participacoes'

    """
    chave primária composta entre filme_id e pessoas_id
    """
    filme_id = Column(Uuid(as_uuid=True), ForeignKey('filmes.id'), primary_key=True)
    pessoa_id = Column(Uuid(as_uuid=True), ForeignKey('pessoas.id'), primary_key=True)

    inicio_trabalho = Column(Date)
    fim_trabalho = Column(Date)
    remuneracao = Column(DECIMAL(12, 2))
    observacoes = Column(Text)

    funcao_tecnica_id = Column(Uuid(as_uuid=True), ForeignKey('funcoes_tecnicas.id'))
    funcao_tecnica = relationship("FuncaoTecnica", back_populates="participacao")

    # association between Participacao → Pessoa
    pessoa = relationship('Pessoa', back_populates='participacoes')

    # association between Participacao → Filme
    filme = relationship('Filme', back_populates='participacoes')


class FuncaoTecnica(db.Model, BasicRepositoryMixin):
    __tablename__ = 'funcoes_tecnicas'
    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nome = Column(String(250), nullable=False)
    categoria = Column(String(250), nullable=False)
    descricao = Column(Text)
    participacao = relationship("Participacao", back_populates="funcao_tecnica")
