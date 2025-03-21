from abc import ABC, abstractmethod
from typing import (
    TypeAlias,
)

from app.sbom.parser.artifact import Artifact
from app.sbom.parser.sbom_info import SBOMInfo

SBOM: TypeAlias = dict


class SBOMParser(ABC):
    @classmethod
    @abstractmethod
    def parse_sbom(cls, sbom: SBOM, sbom_info: SBOMInfo) -> list[Artifact]:
        raise NotImplementedError()
