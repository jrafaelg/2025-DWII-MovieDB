from flask import current_app
from flask_login import current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileField
from wtforms.fields.simple import BooleanField, HiddenField, PasswordField, StringField, SubmitField
from wtforms.validators import Email, EqualTo, InputRequired, Length, ValidationError


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
        Verifica se já existe um usuário com o email informado.

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
        mensagens = [f"A sua senha precisa ter pelo menos {min_caracteres} caracteres"]

        for teste in lista_de_testes:
            if current_app.config.get(teste.config, False):
                senha_valida = senha_valida and (re.search(teste.re, field.data) is not None)
                mensagens.append(teste.mensagem)

        mensagem = ", ".join(mensagens)
        pos = mensagem.rfind(', ')
        if pos > -1:
            mensagem = mensagem[:pos] + ' e ' + mensagem[pos + 2:]

        if not senha_valida:
            raise ValidationError(mensagem)

        return


class DadosImutaveisDoUsuario:
    """
    Validador WTForms para garantir que um campo não seja modificado pelo usuário no lado do
    cliente.

    Este validador compara o valor do campo com o valor correspondente no
    objeto `current_user`. Se os valores forem diferentes, uma `ValidationError`
    é levantada.

    Casos limite:
        - Usuário não autenticado: lança exceção.
        - Campo 'id' convertido para string para garantir comparação correta.
    """

    def __init__(self, field_name: str, message: str = None) -> None:
        """
        Inicializa o validador de campos imutáveis do usuário.

        Args:
            field_name (str): Nome do atributo no objeto `current_user` a ser comparado.
            message (str, opcional): Mensagem de erro personalizada.

        Design:
            - Permite customização da mensagem de erro.
        """
        self.field_name = field_name
        self.message = message or (
            f"Tentativa de modificação não autorizada do campo {field_name}"
        )

    def __call__(self, form, field) -> None:
        """
        Executa a validação do campo imutável.

        Utiliza logging para registrar tentativas de violação.

        Args:
            form: O formulário WTForms sendo validado.
            field: O campo a ser verificado.

        Raises:
            ValidationError: se o valor do campo for diferente do valor esperado.
        """
        if not current_user.is_authenticated:
            raise ValidationError("Usuário não autenticado")

        expected_value = getattr(current_user, self.field_name)
        if self.field_name == 'id':
            expected_value = str(expected_value)

        if field.data != expected_value:
            current_app.logger.warning("Violação da integridade dos dados")
            current_app.logger.warning(
                    f"Usuário {current_user.id} tentou "
                    f"modificar o campo {self.field_name} "
                    f"de '{expected_value}' para '{field.data}'"
            )
            raise ValidationError(self.message)


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
    id = HiddenField(validators=[DadosImutaveisDoUsuario('id')])

    nome = StringField(
            label="Nome",
            validators=[InputRequired(message="É obrigatório informar um nome para cadastro"),
                        Length(max=60,
                               message="O nome pode ter até 60 caracteres")])
    email = StringField(
            label="Email",
            validators=[DadosImutaveisDoUsuario('email')])

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
