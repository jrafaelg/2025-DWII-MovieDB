import jwt
from flask import current_app
from time import time
import uuid
from typing import Any, Dict, Optional

def create_jwt_token(action: str = "",
                     sub: Any = None,
                     expires_in: int = 600,
                     extra_data: Optional[Dict[str, str]] = None) -> str:
    """
    Cria um token JWT com os parâmetros fornecidos.

    Args:
        action: A ação para a qual o token está sendo usado (opcional).
        sub: O assunto do token (por exemplo, ID do usuário).
        expires_in: O tempo de expiração do token em segundos. Default de 10min
        extra_data: Dados adicionais para incluir no payload (opcional).

    Returns:
        O token JWT codificado.

    Raises:
        ValueError: Se o objeto 'sub' não puder ser convertido em string.
    """

    if not hasattr(type(sub), '__str__'):  # isinstance(sub, (str, int, float, uuid.UUID)):
        raise ValueError(f"Tipo de objeto 'sub' inválido: {type(sub)}")

    agora = int(time())
    payload = {
        'sub'   : str(sub),
        'iat'   : agora,
        'nbf'   : agora,
        'exp'   : agora + expires_in,
        'action': action.lower()
    }
    if extra_data is not None and isinstance(extra_data, dict):
        payload['extra_data'] = extra_data
    return jwt.encode(payload=payload,
                      key=current_app.config.get('SECRET_KEY'),
                      algorithm='HS256')


def verify_jwt_token(token: str) -> Dict[str, Any]:
    """
     Verifica a validade de um token JWT e retorna as reivindicações associadas.

     Args:
         token (str): O token JWT a ser verificado.

     Returns:
         Dict[str, Any]: Um dicionário contendo as reivindicações do token. As chaves incluem:
             - 'valid' (bool): Indica se o token é válido ou não.
             - 'user_id' (UUID): O ID do usuário associado ao token, se fornecido.
             - 'action' (str): A ação associada ao token, se fornecida.
             - 'age' (int): A idade do token, em segundos desde a assinatura.
             - 'extra_data' (dict): Dados adicionais incluídos no token, se fornecidos.

     Raises:
         - jwt.ExpiredSignatureError: Se o token JWT estiver expirado.
         - jwt.InvalidTokenError: Se o token JWT for inválido.
         - ValueError: Se ocorrer um erro ao decodificar o token.

     """
    claims: Dict[str, Any] = {'valid': False}

    try:
        payload = jwt.decode(token,
                             key=current_app.config.get('SECRET_KEY'),
                             algorithms=['HS256'])

        claims.update({'valid'  : True,
                       'user_id': uuid.UUID(payload.get('sub', None)),
                       'action' : payload.get('action', None)})

        if 'iat' in payload:
            claims.update({'age': int(time()) - int(payload.get('iat'))})

        if 'extra_data' in payload:
            claims.update({'extra_data': payload.get('extra_data')})

    except jwt.ExpiredSignatureError as e:
        current_app.logger.error("JWT Token Expired: %s", e)
        claims.update({'reason': "expired"})

    except jwt.InvalidTokenError as e:
        current_app.logger.error("Invalid JWT Token: %s", e)
        claims.update({'reason': "invalid"})

    except ValueError as e:
        current_app.logger.error("ValueError: %s", e)
        claims.update({'reason': "valueerror"})

    return claims
