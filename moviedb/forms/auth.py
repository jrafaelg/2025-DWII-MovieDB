from flask_wtf import FlaskForm
from wtforms.fields.simple import BooleanField, PasswordField, StringField, SubmitField
from wtforms.validators import Email, EqualTo, InputRequired, Length, ValidationError


class UniqueEmail(object):
    """
    Validador WTForms para garantir que o email informado não
    está cadastrado no sistema.

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
    Validador WTForms para garantir que a senha informada atende aos requisitos de complexidade definidos.

    Args:
        tamanho (int): Tamanho mínimo da senha.
        maiusculas (bool): Se deve exigir ao menos uma letra maiúscula.
        minusculas (bool): Se deve exigir ao menos uma letra minúscula.
        digitos (bool): Se deve exigir ao menos um dígito.
        simbolos (bool): Se deve exigir ao menos um símbolo.
        message (str, opcional): Mensagem de erro personalizada.
    """
    def __init__(self,
                 tamanho: int = 8,
                 maiusculas: bool = False,
                 minusculas: bool = False,
                 digitos: bool = False,
                 simbolos: bool = False,
                 message: str = None):
        """
        Inicializa o validador de senha complexa com os requisitos especificados.

        Args:
            tamanho (int): Tamanho mínimo da senha.
            maiusculas (bool): Exige letra maiúscula.
            minusculas (bool): Exige letra minúscula.
            digitos (bool): Exige dígito.
            simbolos (bool): Exige símbolo.
            message (str, opcional): Mensagem de erro personalizada.
        """
        self.tamanho = tamanho
        self.maiusculas = maiusculas
        self.minusculas = minusculas
        self.digitos = digitos
        self.simbolos = simbolos
        if message is None:
            message = [ f"A senha deve ter ao menos {tamanho} caracteres" ]
            if maiusculas:
                message.append("uma letra maiúscula")
            if minusculas:
                message.append("uma letra minúscula")
            if digitos:
                message.append("um dígito")
            if simbolos:
                message.append("um símbolo")
            message = ", ".join(message)
        self.message = message

    def __call__(self, form, field):
        """
        Realiza a validação da senha conforme os requisitos definidos.

        Args:
            form: O formulário sendo validado.
            field: O campo de senha a ser verificado.

        Raises:
            ValidationError: Se a senha não atender aos requisitos de complexidade.
        """
        import re
        senha = field.data
        valida = True
        valida = valida and (len(senha) >= self.tamanho)
        if self.maiusculas:
            valida = valida and (re.search(r'[A-Z]', senha) is not None)
        if self.minusculas:
            valida = valida and (re.search(r'[a-z]', senha) is not None)
        if self.digitos:
            valida = valida and (re.search(r'\d', senha) is not None)
        if self.simbolos:
            valida = valida and (re.search(r'\W', senha) is not None)
        if not valida:
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
                        SenhaComplexa(tamanho=10, maiusculas=True, minusculas=True, digitos=True)
                        ])
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
