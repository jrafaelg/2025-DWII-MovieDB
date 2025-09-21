from enum import Enum


class JWT_action(Enum):
    NO_ACTION = 0
    VALIDAR_EMAIL = 1
    RESET_PASSWORD = 2
    PENDING_2FA = 3

class Autenticacao2FA(Enum):
    WRONG = 0
    TOTP = 1
    BACKUP = 2
    REUSED = 3
