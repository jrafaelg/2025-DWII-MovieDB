import uuid
from typing import Any, Dict, Optional, Self, Union

import sqlalchemy as sa

from moviedb import db


class BasicRepositoryMixin:
    """
    Mixin básico para repositórios SQLAlchemy, fornecendo métodos utilitários
    para operações comuns de consulta.
    """

    @classmethod
    def is_empty(cls) -> bool:
        """
        Verifica se a tabela associada à classe está vazia.

        Returns:
            bool: True se não houver registros, False caso contrário.
        """
        return not db.session.execute(sa.select(cls).limit(1)).scalar_one_or_none()

    @classmethod
    def get_by_id(cls, cls_id) -> Optional[Self] | None:
        """
        Busca um registro pelo seu ID.

        Args:
            cls_id: O identificador do registro (UUID ou outro tipo).

        Returns:
            Optional[Self]: Instância encontrada ou None.
        """
        try:
            obj_id = uuid.UUID(str(cls_id))
        except ValueError:
            obj_id = cls_id
        return db.session.get(cls, obj_id)

    @classmethod
    def get_top_n(cls,
                  top_n: int = -1,
                  order_by: Optional[str] = None):
        """
        Retorna os top N registros, opcionalmente ordenados por um atributo.

        Args:
            top_n (int): Número de registros a retornar. Se -1, retorna todos.
            order_by (Optional[str]): Nome do atributo para ordenação.

        Returns:
            Result: Iterável de instâncias.
        """
        sentenca = sa.select(cls)
        if order_by is not None and hasattr(cls, order_by):
            sentenca = sentenca.order_by(getattr(cls, order_by))
        if top_n > 0:
            sentenca = sentenca.limit(top_n)
        return db.session.execute(sentenca).scalars()

    @classmethod
    def get_all(cls,
                order_by: Optional[str] = None):
        """
        Retorna todos os registros, opcionalmente ordenados por um atributo.

        Args:
            order_by (Optional[str]): Nome do atributo para ordenação.

        Returns:
            Result: Iterável de instâncias.
        """
        sentenca = sa.select(cls)
        if order_by is not None and hasattr(cls, order_by):
            sentenca = sentenca.order_by(getattr(cls, order_by))
        return db.session.execute(sentenca).scalars()

    @classmethod
    def get_by_composed_id(cls,
                           cls_dict_id: Dict[str, Any]) -> Optional[Self]:
        """
        Busca um registro por um ID composto.

        Args:
            cls_dict_id (Dict[str, Any]): Dicionário com os campos do ID composto.

        Returns:
            Optional[Self]: Instância encontrada ou None.
        """
        for k, v in cls_dict_id.items():
            try:
                cls_dict_id[k] = uuid.UUID(str(v))
            except ValueError:
                cls_dict_id[k] = v
        return db.session.get(cls, cls_dict_id)

    @classmethod
    def get_first_or_none_by(cls,
                             atributo: str,
                             valor: Union[str, int, uuid.UUID],
                             casesensitive: bool = True) -> Optional[Self]:
        """
        Busca o primeiro registro que corresponde ao valor de um atributo.

        Args:
            atributo (str): Nome do atributo para busca.
            valor (Union[str, int, uuid.UUID]): Valor a ser buscado.
            casesensitive (bool): Se a busca deve ser case sensitive.

        Returns:
            Optional[Self]: Instância encontrada ou None.

        Raises:
            TypeError: Se a busca for case insensitive e o valor não for str.
        """
        registro = None
        if hasattr(cls, atributo):
            if casesensitive:
                registro = db.session.execute(
                        sa.select(cls).
                        where(getattr(cls, atributo) == valor).
                        limit(1)
                ).scalar_one_or_none()
            else:
                if isinstance(valor, str):
                    # noinspection PyTypeChecker
                    registro = db.session.execute(
                            sa.select(cls).
                            where(sa.func.lower(getattr(cls, atributo)) == sa.func.lower(valor)).
                            limit(1)
                    ).scalar_one_or_none()
                else:
                    raise TypeError("Para a operação case insensitive, o "
                                    f"atributo \"{atributo}\" deve ser da classe str")
        return registro
