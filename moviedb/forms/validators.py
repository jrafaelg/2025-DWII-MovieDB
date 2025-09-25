from typing import Any, Callable, Optional

from flask import current_app
from wtforms.validators import ValidationError


class CampoImutavel:
    """
    Validador WTForms genérico para garantir que um campo não seja modificado pelo usuário no
    lado do cliente.

    Usa introspecção para acessar o objeto de referência através do formulário.

    Exemplos de uso:
        class ProfileForm(FlaskForm):
            def __init__(self, obj=None, **kwargs):
                super().__init__(**kwargs)
                self.reference_obj = obj or current_user

            id = HiddenField(validators=[CampoImutavel('id')])
            email = StringField(validators=[CampoImutavel('email')])
    """

    def __init__(self,
                 field_name: str,
                 attr_name: Optional[str] = None,
                 message: Optional[str] = None,
                 converter: Optional[Callable[[Any], Any]] = None) -> None:
        """
        Inicializa o validador de campos imutáveis genérico.

        Args:
            field_name (str): Nome do campo no formulário.
            attr_name (str, opcional): Nome do atributo no objeto de referência
                                     (padrão: mesmo que field_name).
            message (str, opcional): Mensagem de erro personalizada.
            converter (Callable, opcional): Função para converter o valor de referência.
        """
        self.field_name = field_name
        self.attr_name = attr_name or field_name
        self.converter = converter or (str if field_name == 'id' else lambda x: x)
        self.message = message or f"Tentativa de modificação não autorizada do campo {field_name}"

    def __call__(self, form, field) -> None:
        """
        Executa a validação do campo imutável usando introspecção no formulário.

        Args:
            form: O formulário WTForms sendo validado.
            field: O campo a ser verificado.

        Raises:
            ValidationError: se o valor do campo for diferente do valor esperado.
        """
        # Verifica se o formulário tem um objeto de referência
        if not hasattr(form, 'reference_obj'):
            raise ValidationError("Formulário deve ter atributo 'reference_obj'")

        reference_obj = form.reference_obj
        if reference_obj is None:
            raise ValidationError("Objeto de referência não pode ser None")

        try:
            expected_value = getattr(reference_obj, self.attr_name)
            expected_value = self.converter(expected_value)
        except AttributeError:
            current_app.logger.error("Atributo '%s' não encontrado no objeto %s" %
                                     (self.attr_name, type(reference_obj).__name__,))
            raise ValidationError("Erro interno na validação")
        except Exception as e:
            current_app.logger.error("Erro ao processar valor de referência para %s: %s" %
                                     (self.field_name, str(e),))
            raise ValidationError("Erro interno na validação")

        if field.data != expected_value:
            current_app.logger.warning(
                "Violação da integridade: campo %s alterado de '%s' para '%s'" %
                (self.field_name, expected_value, field.data,))
            raise ValidationError(self.message)
