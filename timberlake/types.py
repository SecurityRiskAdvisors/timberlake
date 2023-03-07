from typing import List, Optional, Union, TypeVar, Any, Dict, Callable, Tuple
from abc import ABC
import json
from enum import Enum
from uuid import uuid4
from dataclasses import dataclass, field
from py_attire_schema.schemas import Procedure, ProcedureId, Step, OutputItem
from boto3.resources.base import ServiceResource as BotoLibServiceResource
from boto3.session import Session as BotoLibSession
from botocore.client import BaseClient as BotoLibBaseClient

from .common import zulu_time_str


BotoResource = TypeVar("BotoResource", bound=BotoLibServiceResource)
BotoClient = TypeVar("BotoClient", bound=BotoLibBaseClient)
BotoSession = TypeVar("BotoSession", bound=BotoLibSession)
BotoClientOrSession = Union[BotoSession, BotoClient]


@dataclass
class TestCaseMetadata:
    author: str
    x_vectr_id: str


class CloudProvider(Enum):
    aws = 1
    azure = 2
    gcp = 3
    other = 4


@dataclass
class MitreMetadata:
    id: str
    tactic: str  # tactic id


class BlockPhase(Enum):
    execution = 1
    setup = 2
    cleanup = 3


class BlockType(Enum):
    inline = 1
    file = 2


@dataclass
class VectrApiCredentials:
    access_key: str
    secret_key: str

    def validate(self):
        raise NotImplementedError


@dataclass
class VectrConfig:
    use_vectr: bool
    # these are required when use_vectr == True
    host: Optional[str]
    api_credentials: Optional[VectrApiCredentials]
    assessment: Optional[str]
    database: Optional[str]
    attire_log: Optional[str]

    def __post_init__(self):
        if self.use_vectr:
            for attr in self.__annotations__.keys():
                if getattr(self, attr) is None:
                    raise Exception(f"Missing value for VECTR config option {attr}")


@dataclass
class TestCaseLocation:
    directory: str
    recurse: bool = True


@dataclass
class VectrObject:
    name: str
    id: str


@dataclass
class VectrTestCase:
    name: str
    description: str
    phase: str  # vectr phase name
    technique: str  # mitre technique id
    # time format ISO-8601Z epoch ms
    attackStart: float
    attackStop: float

    # optional/static items
    outcomeNotes: Optional[str]
    operatorGuidance: Optional[str]
    targets: Optional[List[str]] = field(default_factory=list)
    sources: Optional[List[str]] = field(default_factory=list)

    def __post_init__(self):
        from timberlake.settings import global_settings

        self.organization = global_settings.org_id
        self.tags = ["timberlake"]

    def gen_attire_procedure(self, test_case_id: str, command_logs: str) -> dict:
        """generate an ATTiRe procedure block for the test case"""
        procedure = json.loads(
            Procedure(
                procedure_name=self.name,
                procedure_description=self.description,
                procedure_id=ProcedureId(type="guid", id=str(uuid4())),
                mitre_technique_id=self.technique,
                order=1,
                steps=[
                    Step(
                        command=command_logs,
                        executor="timberlake",
                        order=1,
                        time_start=zulu_time_str(),
                        time_stop=zulu_time_str(),
                        output=[OutputItem(content="", level="", type="")],
                    )
                ],
            ).json(by_alias=True)
        )
        procedure["x-vectr-io-testcase-id"] = test_case_id  # field not exposed by schema lib
        return procedure
