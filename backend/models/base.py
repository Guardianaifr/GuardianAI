from typing import Annotated, Any, Optional, Union, get_args, get_origin
from pydantic import BaseModel as PydanticBaseModel, Field


class BaseModel(PydanticBaseModel):
    def __init_subclass__(cls, **kwargs):
        annotations = getattr(cls, "__annotations__", {})
        for field_name, ann in list(annotations.items()):
            is_annotated = get_origin(ann) is Annotated
            base_type = ann
            metadata = []
            if is_annotated:
                args = get_args(ann)
                base_type = args[0]
                metadata = list(args[1:])

            is_str = False
            is_optional_str = False

            if base_type is str:
                is_str = True
            elif base_type == Optional[str] or base_type == Union[str, None]:
                is_optional_str = True
            elif get_origin(base_type) is Union:
                args = get_args(base_type)
                if str in args:
                    if type(None) in args:
                        is_optional_str = True
                    else:
                        is_str = True

            if is_str or is_optional_str:
                has_max_length = False
                for meta in metadata:
                    if hasattr(meta, "max_length"):
                        has_max_length = True
                        break

                field_val = getattr(cls, field_name, None)
                from pydantic.fields import FieldInfo
                if isinstance(field_val, FieldInfo):
                    for meta in field_val.metadata:
                        if hasattr(meta, "max_length"):
                            has_max_length = True
                            break
                    if not has_max_length:
                        from annotated_types import MaxLen
                        field_val.metadata.append(MaxLen(512))
                else:
                    if not has_max_length:
                        new_field = Field(max_length=512)
                        annotations[field_name] = Annotated[base_type, new_field]
                        if field_val is not None:
                            setattr(cls, field_name, Field(field_val, max_length=512))

        super().__init_subclass__(**kwargs)


__all__ = ["BaseModel"]
