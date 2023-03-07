import pathlib
import os
import io
import jinja2
import logging
from contextlib import contextmanager
from marshmallow_enum import EnumField

from .types import (
    Optional,
    List,
    Any,
    Dict,
    CloudProvider,
    MitreMetadata,
    BlockPhase,
    BlockType,
    VectrTestCase,
    dataclass,
    TestCaseMetadata,
    field,
)
from .common import FileLoaderMixin, get_public_ip
from .mitre import MITRE_TACTIC_ID_TO_NAME
from .log import logger


@dataclass
class StepBlock:
    content: str
    phase: BlockPhase = EnumField(BlockPhase)
    type: BlockType = EnumField(BlockType)
    ignore_errors: bool = False
    arguments: Dict[Any, Any] = field(default_factory=dict)
    result: str = None

    @property
    def parent(self):
        return self.__parent

    @parent.setter
    def parent(self, v: "TestCase"):
        self.__parent = v

    def __post_init__(self):
        self.profiles: List[str] = ["default"]
        self.tc_file_path: pathlib.Path = None

        self._log_buffer = io.StringIO()
        self._log_sink = logging.StreamHandler(self._log_buffer)

    def set_exec_value(self, key, value):
        """function for storing values across a test case"""
        if key not in self.parent.value_store:
            self.parent.value_store[key] = value
            logger.info(f'setting value of "{key}" to "{value}" ')

    def get_exec_value(self, key):
        """function for retrieving values across a test case"""
        value = self.parent.value_store[key]
        logger.info(f'resolved value of "{key}" to "{value}"')
        return value

    @contextmanager
    def logger(self):
        """context handler to temporarily add additional logging sink to global Timberlake logger"""
        try:
            logger.addHandler(self._log_sink)
            yield logger
        finally:
            logger.removeHandler(self._log_sink)

    def get_logs(self):
        """get all logs captured by test case logger"""
        self._log_buffer.seek(0)
        return self._log_buffer.read()

    def render_content(self, overrides: dict = None) -> str:
        """render the test case block using the test case arguments"""
        overrides = dict() if overrides is None else overrides
        if self.type == BlockType.file:
            if not os.path.isabs(self.content) and self.tc_file_path.exists():
                # if the block uses a file as its content rather than inline Python code,
                # the file will be looked for relative to the testcase unless the path is absolute
                # ex:
                #   /timberlake
                #       /testcases
                #         \_ testcase.yml
                #         \_ foo.py
                #   /etc
                #     \_ foo.py
                #  setting the content to "foo.py" will return the contents of the first scenario above (/timberlake/testcases/foo.py)
                #   and setting the content to "/etc/foo.py" will return the contents of the second scenario (/etc/foo.py)
                path = self.tc_file_path.parent.joinpath(self.content).resolve()
            else:
                path = pathlib.Path(self.content)
            content: str = path.read_text()
        else:
            content = self.content

        arguments = {**self.arguments, **overrides}
        rendered = jinja2.Environment().from_string(source=content).render(arguments)
        return rendered

    def execute(self, *render_args, **render_kwargs) -> bool:
        """execute the block and log details to logging sink"""

        # this logging sink is primarily used to isolate the logging for specifically the action(s)
        # performed in this block so that it can be added to the generated attire log
        # the information is still logged to the main log file
        with self.logger():
            try:
                # TODO: providers should be dynamically loaded rather than be part of module
                #   will need to move .aws out of module as well
                #   then create some expected interface for these providers
                #   dynamic providers should also populate the CloudProvider enum
                if self.parent.provider == CloudProvider.aws:
                    from .aws import generate_aws_ctx

                    ctx = generate_aws_ctx(profiles=self.profiles)
                else:
                    raise NotImplementedError(f"Provider {self.parent.provider} not implemented")

                global_ctx = {"get_value": self.get_exec_value, "set_value": self.set_exec_value, "log": logger.info}
                globalsd = {**locals(), **globals(), **ctx, **global_ctx}

                rendered = self.render_content(**render_kwargs)
                exec(rendered, globalsd, globalsd)
                if "result" in globalsd:
                    self.result = globalsd["result"]
                passed = True

            except Exception as e:
                logging.error(f"Exception hit: {e}")
                passed = False

        return True if self.ignore_errors else passed


@dataclass
class TestCaseStep:
    name: str
    block: StepBlock


@dataclass
class TestCase(FileLoaderMixin):
    name: str
    description: str
    metadata: Optional[TestCaseMetadata]
    mitre: Optional[MitreMetadata]
    permissions: Optional[List[str]]
    steps: List[TestCaseStep]
    provider: CloudProvider = CloudProvider.aws
    arguments: Dict[Any, Any] = field(default_factory=dict)

    def __post_init__(self):
        self.value_store = {}

        # update the args for all blocks to use the parents args
        #
        # this method will also be called on init via schema.load()
        for step in self.steps:
            step.block.arguments = self.arguments
            step.block.tc_file_path = self.original_file_path
            # to do remove these above then reference parent directly from child
            step.block.parent = self

    def to_vectr_testcases(self, time) -> List[VectrTestCase]:
        """convert the test case details to a form usable in VECTR"""
        test_cases = []
        exec_steps = [step for step in self.steps if step.block.phase == BlockPhase.execution]
        for step in exec_steps:
            test_cases.append(
                VectrTestCase(
                    name=self.name,
                    description=self.description,
                    phase=MITRE_TACTIC_ID_TO_NAME.get(self.mitre.tactic),
                    technique=self.mitre.id,
                    outcomeNotes="\n".join(self.permissions),
                    operatorGuidance=step.block.render_content(),
                    attackStop=time,
                    attackStart=time,
                    sources=[get_public_ip()],
                )
            )
        return test_cases
