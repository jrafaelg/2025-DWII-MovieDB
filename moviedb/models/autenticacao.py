import uuid
from base64 import b64decode, b64encode

from flask import current_app
from flask_login import UserMixin
from sqlalchemy import Boolean, Column, select, String, Text, Uuid

from moviedb import db
from moviedb.models.mixins import BasicRepositoryMixin


def normalizar_email(email: str) -> str:
    """
    Normaliza um endereço de e-mail utilizando a biblioteca email_validator.

    Args:
        email (str): Endereço de e-mail a ser normalizado.

    Returns:
        str: E-mail normalizado em letras minúsculas.

    Raises:
        EmailNotValidError: Se o e-mail fornecido não for válido.
    """
    from email_validator import validate_email
    from email_validator.exceptions import EmailNotValidError
    try:
        return validate_email(email, check_deliverability=False).normalized.lower()
    except EmailNotValidError:
        raise


class User(db.Model, BasicRepositoryMixin, UserMixin):
    __tablename__ = "usuarios"

    id = Column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    nome = Column(String(60), nullable=False)
    email_normalizado = Column(String(180), nullable=False, unique=True, index=True)
    password_hash = Column(String(256), nullable=False)
    ativo = Column(Boolean, nullable=False, default=False)

    com_foto = Column(Boolean, default=False)
    foto_base64 = Column(Text, nullable=True, default=None)
    foto_mime = Column(String(32), nullable=True, default=None)

    @property
    def email(self):
        return self.email_normalizado

    @email.setter
    def email(self, value):
        self.email_normalizado = normalizar_email(value)

    @property
    def is_active(self):
        return self.ativo

    def get_id(self):  # https://flask-login.readthedocs.io/en/latest/#alternative-tokens
        return f"{str(self.id)}|{self.password[-15:]}"

    @property
    def password(self):
        return self.password_hash

    @password.setter
    def password(self, value):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(value)

    @classmethod
    def get_by_email(cls, email: str):
        return db.session.execute(
                select(cls).
                where(User.email_normalizado == normalizar_email(email))
        ).scalar_one_or_none()

    def check_password(self, password) -> bool:
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

    @property
    def foto(self) -> (bytes, str):
        if self.com_foto:
            data = b64decode(self.foto_base64)
            mime_type = self.foto_mime
        else:
            data = None
            mime_type = None
        return data, mime_type

    @foto.setter
    def foto(self, value):
        """
        Setter para a foto do usuário.

        Atualiza os campos relacionados à foto do usuário. Se o valor for None,
        remove a foto e limpa os campos associados. Caso contrário, tenta armazenar
        a foto em base64 e o tipo MIME. Lida com o caso em que value não possui os
        métodos/atributos esperados, registrando o erro.

        Args:
            value: Um arquivo com métodos `read()` e atributo `mimetype`, ou None.
        """
        if value is None:
            self.com_foto = False
            self.foto_base64 = None
            self.foto_mime = None
        else:
            try:
                self.com_foto = True
                self.foto_base64 = b64encode(value.read()).decode('utf-8')
                self.foto_mime = value.mimetype
            except AttributeError as e:
                # value não possui read() ou mimetype
                self.com_foto = False
                self.foto_base64 = None
                self.foto_mime = None
                # Registra o erro para depuração
                if hasattr(current_app, "logger"):
                    current_app.logger.error("Erro ao definir foto: %s", str(e))

    def send_email(self, subject: str,
                   body: str) -> bool:
        """
        Envia um e-mail para o usuário utilizando o serviço Postmark.

        Args:
            subject (str): Assunto do e-mail.
            body (str): Corpo do e-mail em texto simples.

        Returns:
            True se conseguir enviar o e-mail, False caso contrário.
        """
        if current_app.config.get('SEND_EMAIL'):
            from postmarker.core import PostmarkClient
            postmark = PostmarkClient(server_token=current_app.config['SERVER_TOKEN'])
            conteudo = postmark.emails.Email(
                    From=current_app.config['EMAIL_SENDER'],
                    To=self.email,
                    Subject=subject,
                    TextBody=body
            )
            response = conteudo.send()
            if hasattr(current_app, "logger"):
                current_app.logger.debug("Email enviado para %s", self.email)
                current_app.logger.debug("Resposta do Postmark: %s", response)
            if response['ErrorCode'] != 0:
                if hasattr(current_app, "logger"):
                    current_app.logger.error("Erro ao enviar email para %s: %s",
                                         self.email, response['Message'])
                return False
        else:
            if hasattr(current_app, "logger"):
                current_app.logger.debug("Mensagem que SERIA enviada")
                current_app.logger.debug("From: %s", current_app.config['EMAIL_SENDER'])
                current_app.logger.debug("To: %s", self.email)
                current_app.logger.debug("Subject: %s", subject)
                current_app.logger.debug("", )
                current_app.logger.debug("%s", body)
        return True
