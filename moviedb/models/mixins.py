import uuid
from typing import Optional, Self

import sqlalchemy as sa

from moviedb import db


class BasicRepositoryMixin:
    @classmethod
    def is_empty(cls) -> bool:
        return not db.session.execute(sa.select(cls).limit(1)).scalar_one_or_none()

    @classmethod
    def get_by_id(cls, cls_id) -> Optional[Self] | None:
        try:
            obj_id = uuid.UUID(str(cls_id))
        except ValueError:
            obj_id = cls_id
        return db.session.get(cls, obj_id)
