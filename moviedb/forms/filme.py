from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed
from wtforms.fields.numeric import IntegerField, DecimalField
from wtforms.fields.simple import HiddenField, StringField, BooleanField, TextAreaField, FileField
from wtforms.validators import InputRequired, Length, NumberRange


class AddForm(FlaskForm):


    """
    lancado = Column(Boolean, nullable=False)
    duracao = Column(Integer(), nullable=False)
    sinopse = Column(Text())
    orcamento = Column(DECIMAL)
    faturamento_lancamento = Column(DECIMAL(precision=2), default=0)
    poster_principal = Column(Text, nullable=True, default=None)
    link_trailer = Column(Text, nullable=True, default=None)
    """

    titulo_original = StringField(
            label="Título original",
            validators=[
                InputRequired(message="É obrigatório informar um título para cadastro"),
                Length(max=200, message="O nome pode ter até 200 caracteres")
            ]
    )

    titulo_nacional = StringField(
        label="titulo nacional",
        validators=[
            InputRequired(message="É obrigatório informar um título nacional para cadastro"),
            Length(max=200, message="O nome pode ter até 200 caracteres")
        ]
    )

    ano_lancamento = IntegerField(
        label="Ano de lançamento",
        validators=[
            InputRequired(message="Informe o ano de lançamento"),
            Length(min=4, max=4, message="O ano deve ter 4 dígitos" ),
            NumberRange(min=1900, message="O ano ser maior que 1900")
        ]
    )

    lancado = BooleanField(
        label="Lancado",
        default=False
    )

    duracao = IntegerField(
        label="Duracao",
        validators=[
            InputRequired(message="Informe o tempo de duração"),
            Length(min=2, max=3, message="Corrija aqui."),
            NumberRange(min=10, message="O tempo deve ter 10 minutos no mínimo.")
        ]
    )

    sinopse = TextAreaField(
        label="Sinopse",
        validators=[
            Length(min=4, message="A sinopse deve ter no mínimo 4 letras."),
        ]
    )

    orcamento = DecimalField(
        label="Orçamento",
        places=2,
        validators=[

        ]
    )

    faturamento_lancamento = DecimalField(
        label="Faturamento no lançamento",
        places=2,
        validators=[

        ]
    )

    poster_principal = FileField(
            label="Poster",
            validators=[
                FileAllowed(upload_set=['jpg', 'jpeg', 'png'], message="Apenas arquivos JPG ou PNG")
            ]
    )






