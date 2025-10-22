from enum import Enum


class JWT_action(Enum):
    """
    Enumeração que define as ações possíveis para tokens JWT.

    Attributes:
       NO_ACTION: Nenhuma ação específica indicada
       VALIDAR_EMAIL: Token usado para validação de email
       RESET_PASSWORD: Token usado para reset de senha
       PENDING_2FA: Token usado para indicar pendência de autenticação de dois fatores
    """
    NO_ACTION = 0
    VALIDAR_EMAIL = 1
    RESET_PASSWORD = 2
    PENDING_2FA = 3


class Autenticacao2FA(Enum):
    """ Enumeração que define os resultados possíveis da autenticação de dois fatores.

    Attributes:
        WRONG: Código de autenticação incorreto
        TOTP: Autenticação bem-sucedida via TOTP (Time-based One-Time Password)
        BACKUP: Autenticação bem-sucedida via código de backup
        REUSED: Código de autenticação reutilizado (inválido)
    """
    WRONG = 0
    TOTP = 1
    BACKUP = 2
    REUSED = 3
