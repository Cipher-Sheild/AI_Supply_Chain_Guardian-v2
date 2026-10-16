"""Typed public wrapper additions; detector contract version 1.0 is unchanged."""
from typing import Literal
from pydantic import ConfigDict,Field
from app.schemas import TrustScoreResult
class PerFileOutcome(TrustScoreResult):
    model_config=ConfigDict(extra='forbid')
    scoring:dict=Field(default_factory=dict)
    index:int=Field(ge=0)
    filename:str | None = None
    coverage:Literal['full','partial','none']='none'
    scan_status:Literal['final','provisional']='final'
