from flask_login import current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField
from wtforms.fields.simple import BooleanField, HiddenField, PasswordField, StringField, SubmitField
from wtforms.validators import Email, EqualTo, InputRequired, Length, ValidationError

from moviedb.forms.validators import CampoImutavel


class UniqueEmail(object):
    """
    Validador WTForms para garantir que o email informado não está cadastrado no sistema.

    Args:
        message (str, opcional): Mensagem de erro personalizada.
    """

    def __init__(self, message=None):
        if not message:
            message = "Já existe um usuário com este email"
        self.message = message

    def __call__(self, form, field):
        """
        Verifica se um email já está cadastrado.

        Args:
            form: O formulário sendo validado.
            field: O campo de email a ser verificado.

        Raises:
            ValidationError: Se o email já estiver cadastrado.
        """
        from moviedb.models.autenticacao import User
        if User.get_by_email(field.data):
            raise ValidationError(self.message)


class SenhaComplexa(object):
    """
    Validador WTForms para garantir que a senha informada atende aos requisitos de complexidade
    definidos.

    Os requisitos são definidos pelas seguintes chaves inteiras e booleanas no
    dicionário de configuração da aplicação:

    - PASSWORD_MIN: 8
    - PASSWORD_MINUSCULA: false
    - PASSWORD_NUMERO: false
    - PASSWORD_SIMBOLO: false
    - PASSWORD_MAIUSCULA: false
    """

    def __init__(self):
        pass

    def __call__(self, form, field):
        """
        Realiza a validação da senha conforme os requisitos definidos.

        Args:
            form: O formulário sendo validado.
            field: O campo de senha a ser verificado.

        Raises:
            ValidationError: Se a senha não atender aos requisitos de complexidade.
        """
        from flask import current_app
        import re
        from collections import namedtuple

        Teste = namedtuple('Teste', ['config', 'mensagem', 're'])

        lista_de_testes = [
            Teste('PASSWORD_MAIUSCULA', "letras maiúsculas", r'[A-Z]'),
            Teste('PASSWORD_MINUSCULA', "letras minúsculas", r'[a-z]'),
            Teste('PASSWORD_NUMERO', "números", r'\d'),
            Teste('PASSWORD_SIMBOLO', "símbolos especiais", r'\W')
        ]

        min_caracteres = current_app.config.get('PASSWORD_MIN', 8)
        senha_valida = (len(field.data) >= min_caracteres)
        mensagens = [f"pelo menos {min_caracteres} caracteres"]

        for teste in lista_de_testes:
            if current_app.config.get(teste.config, False):
                senha_valida = senha_valida and (re.search(teste.re, field.data) is not None)
                mensagens.append(teste.mensagem)

        mensagem = "A sua senha precisa conter: "
        if len(mensagens) > 1:
            mensagem = mensagem + " e ".join([", ".join(mensagens[:-1]), mensagens[-1]])
        else:
            mensagem = mensagem + mensagens[0]
        mensagem = mensagem + "."

        if not senha_valida:
            raise ValidationError(mensagem)

        return


class RegistrationForm(FlaskForm):
    nome = StringField(
            label="Nome",
            validators=[InputRequired(message="É obrigatório informar um nome para cadastro"),
                        Length(max=60, message="O nome pode ter até 60 caracteres")])
    email = StringField(
            label="Email",
            validators=[InputRequired(message="É obrigatório informar um email para cadastro"),
                        Email(message="Informe um email válido"),
                        Length(max=180, message="O email pode ter até 180 caracteres"),
                        UniqueEmail(message="Este email já está cadastrado no sistema")])
    password = PasswordField(
            label="Senha",
            validators=[InputRequired(message="É necessário escolher uma senha"),
                        SenhaComplexa()])
    password2 = PasswordField(
            label="Confirme a senha",
            validators=[InputRequired(message="É necessário repetir a senha"),
                        EqualTo('password', message="As senhas não são iguais")])
    submit = SubmitField("Criar uma conta no sistema")


class LoginForm(FlaskForm):
    email = StringField(
            label="Email",
            validators=[InputRequired(message="É obrigatório informar um email para login"),
                        Email(message="Informe um email válido"),
                        Length(max=180, message="O email pode ter até 180 caracteres")])
    password = PasswordField(
            label="Senha",
            validators=[InputRequired(message="É necessário informar a senha")])
    remember_me = BooleanField(
            label="Permanecer conectado?",
            default=True)
    submit = SubmitField("Entrar")


class SetNewPasswordForm(FlaskForm):
    password = PasswordField(
            label="Nova senha",
            validators=[InputRequired(message="É necessário escolher uma senha"),
                        SenhaComplexa()])
    password2 = PasswordField(
            label="Confirme a nova senha",
            validators=[InputRequired(message="É necessário repetir a nova senha"),
                        EqualTo(fieldname='password',
                                message="As senhão não são iguais")])
    submit = SubmitField("Cadastrar a nova senha")


class AskToResetPasswordForm(FlaskForm):
    email = StringField(
            label="Email",
            validators=[
                InputRequired(message="É obrigatório informar o email para o qual se deseja "
                                      "definir nova senha"),
                Email(message="Informe um email válido"),
                Length(max=180, message="O email pode ter até 180 caracteres")
            ])
    submit = SubmitField("Redefinir a senha")


class ProfileForm(FlaskForm):
    def __init__(self, user=None, **kwargs):
        super().__init__(**kwargs)
        self.reference_obj = user or current_user

    id = HiddenField(validators=[CampoImutavel('id')])

    nome = StringField(
            label="Nome",
            validators=[InputRequired(message="É obrigatório informar um nome para cadastro"),
                        Length(max=60,
                               message="O nome pode ter até 60 caracteres")])
    email = StringField(
            label="Email",
            validators=[CampoImutavel('email', message="O email não pode ser alterado.")])

    usa_2fa = BooleanField(
            label="Ativar o segundo fator de autenticação")

    foto_raw = FileField(
            label="Foto de perfil",
            validators=[FileAllowed(upload_set=['jpg', 'jpeg', 'png'],
                                    message="Apenas arquivos JPG ou PNG")])

    submit = SubmitField("Efetuar as mudanças...")
    remover_foto = SubmitField("e remover foto")


class Read2FACodeForm(FlaskForm):
    codigo = StringField(
            label="Código",
            validators=[
                InputRequired(message="Informe o código fornecido pelo aplicativo autenticador"),
                Length(min=6, max=6)],
            render_kw={'autocomplete': 'one-time-code',
                       'pattern'     : r'^[A-Z0-9]{6}$'})
    submit = SubmitField("Enviar código")
