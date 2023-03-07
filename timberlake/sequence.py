from py_attire_schema.schemas import AttireTarget, ExecutionData
from uuid import uuid4
import json
import pathlib

from .config import TimberlakeConfig
from .vectr import VectrGraphQLClient, upsert_assessment_by_name, upsert_campaign_by_name, create_testcase_in_campaign
from .types import dataclass, BlockPhase, List, Callable, Enum, ABC, TypeVar
from .testcase import TestCase, TestCaseStep, StepBlock
from .log import print_and_log, logger
from .common import epoch_now_ms, local_time_str, zulu_time_str


def order_phases(phases: List[BlockPhase]):
    """given a list of phases, return them in the correct order"""
    phases_ordered = []
    if BlockPhase.setup in phases:
        phases_ordered.append(BlockPhase.setup)
    if BlockPhase.execution in phases:
        phases_ordered.append(BlockPhase.execution)
    if BlockPhase.cleanup in phases:
        phases_ordered.append(BlockPhase.cleanup)
    return phases_ordered


@dataclass
class ExecContext(ABC):
    test_case: TestCase
    step: TestCaseStep
    block: StepBlock
    phase: BlockPhase

    def __post_init__(self):
        self.time: float = epoch_now_ms()


ExecContextType = TypeVar("ExecContextType", bound=ExecContext)


@dataclass
class SequencePostExecContext(ExecContext):
    result: bool


@dataclass
class SequencePreExecContext(ExecContext):
    pass


class HookType(Enum):
    PreExecHook = 1
    PostExecHook = 2


@dataclass
class AttackSequence:
    config: TimberlakeConfig
    phase_names: List[str]

    def _precheck(self):
        """checks performed:
        - at least one test case in test case list
        """
        if len(self.config.test_case_list) <= 0:
            raise Exception("No test cases loaded")

    def _log_details_hook(self, context: SequencePostExecContext):
        # default hook; called after execution and intended to cover logging information from execution
        msg = f"{context.step.block.phase.name} - {context.step.name} - Success: {context.result}"
        msg_type = "info" if context.result else "error"
        print_and_log(msg, msg_type=msg_type)

    def _post_execution_hook(self, context: SequencePostExecContext):
        # default hook; called after execution and intended to cover free-form activities
        pass

    def _pre_execution_hook(self, context: SequencePreExecContext):
        # default hook; called before execution and intended to cover free-form activities
        pass

    def __post_init__(self):
        self._precheck()
        phases = [BlockPhase[phase_name] for phase_name in self.phase_names]
        self.phases = order_phases(phases)
        del self.phase_names

        self._pre_exec_hooks = []
        self._post_exec_hooks = []
        self.register_hooks(hooks=[self._pre_execution_hook], hook_type=HookType.PreExecHook)
        self.register_hooks(hooks=[self._post_execution_hook, self._log_details_hook], hook_type=HookType.PostExecHook)

    def _execute_block_for_phase(self, block: StepBlock, phase: BlockPhase, *args, **kwargs) -> bool:
        return block.execute(*args, **kwargs)

    def _get_hooks_by_type(self, hook_type: HookType) -> List:
        if hook_type == HookType.PreExecHook:
            hooks = self._pre_exec_hooks
        elif hook_type == HookType.PostExecHook:
            hooks = self._post_exec_hooks
        else:
            raise Exception("Unknown hook type")

        return hooks

    def register_hooks(self, hooks: List[Callable], hook_type: HookType):
        # register a hook to run after/before every block execution
        hooks_list = self._get_hooks_by_type(hook_type=hook_type)
        hooks_list.extend(hooks)

    def _call_exec_hooks(self, context: ExecContextType, hook_type: HookType):
        hook_list = self._get_hooks_by_type(hook_type=hook_type)

        for hook in hook_list:
            hook(context=context)

    def execute(self, **exec_kwargs):
        """
        This function handles the main execution sequence logic.
        In order of phases, it will execute each test case.
        Before each test case, it calls the pre-execution hooks with a context
            object that provdies the test case, step, block, and phase
        Then the execution occurs.
        Finally, the post-execution hooks are called with a context object
            that is the same as the pre-execution context but with an added result arg
        Logging is handled as a post-execution hook by default
        """
        # TODO: log sts:GetCallerIdentity info for all profiles before execution? other providers?
        for phase in self.phases:
            logger.info(f"Phase started: {phase.name}")

            for test_case in self.config.test_case_list:  # type: TestCase
                for step in test_case.steps:
                    if step.block.phase == phase:
                        self._call_exec_hooks(
                            context=SequencePreExecContext(
                                test_case=test_case, step=step, block=step.block, phase=phase
                            ),
                            hook_type=HookType.PreExecHook,
                        )
                        result = self._execute_block_for_phase(phase=phase, block=step.block, **exec_kwargs)
                        self._call_exec_hooks(
                            context=SequencePostExecContext(
                                result=result, test_case=test_case, step=step, block=step.block, phase=phase
                            ),
                            hook_type=HookType.PostExecHook,
                        )

            logger.info(f"Phase completed: {phase.name}")


@dataclass
class BasicAttackSequence(AttackSequence):
    def __post_init__(self):
        super().__post_init__()


@dataclass
class VectrAttackSequence(AttackSequence):
    def _precheck(self):
        super()._precheck()

    def __post_init__(self):
        super().__post_init__()
        self.run_id = str(uuid4())

        self._vectr_client = VectrGraphQLClient(config=self.config.vectr)
        campaign_name = f"Timberlake Execution - {local_time_str()}"
        print_and_log(campaign_name)

        self.assessment = upsert_assessment_by_name(
            client=self._vectr_client,
            assessment_name=self.config.vectr.assessment,
            database_name=self.config.vectr.database,
        )
        self.campaign = upsert_campaign_by_name(  # TODO: should error if exists?
            client=self._vectr_client,
            campaign_name=campaign_name,
            asessment_id=self.assessment.id,
            database_name=self.config.vectr.database,
        )

        execution_data = json.loads(
            ExecutionData(
                command="timerblake",
                execution_id=str(uuid4()),
                source="timberlake",
                time_generated=zulu_time_str(),
                # target=AttireTarget(host="", ip="127.0.0.1", path="", user="timberlake"),
            ).json(by_alias=True)
        )  # by alias will convert the "_"s to "-"s for proper import
        # Currently VECTR only supports displaying the IP value when importing an ATTiRe log
        # VECTR itself does not validate this beyond being a string by the py-attire library does
        # To get around this, the target is manually added to the JSON blob
        execution_data["target"] = {"ip": "AWS", "user": "timberlake"}
        self.attire_log = {"attire-version": "1.1", "procedures": [], "execution-data": execution_data}

    def _post_execution_hook(self, context: SequencePostExecContext):
        if context.phase == BlockPhase.execution:
            # only log items that were in the execution phase
            # failed executions are still logged so user must check output log for ERRORs and/or tags
            for vectr_test_case in context.test_case.to_vectr_testcases(time=epoch_now_ms()):
                if context.result is False:
                    vectr_test_case.tags.append("error")
                new_test_case = create_testcase_in_campaign(
                    client=self._vectr_client,
                    database=self.config.vectr.database,
                    campaign_id=self.campaign.id,
                    test_case=vectr_test_case,
                )

                procedure = vectr_test_case.gen_attire_procedure(
                    test_case_id=new_test_case.id, command_logs=context.block.get_logs()
                )
                self.attire_log["procedures"].append(procedure)

    def _pre_execution_hook(self, context: SequencePreExecContext):
        msg = f"{context.step.block.phase.name} - {context.step.name} - Start"
        print_and_log(msg)

    def execute(self, **kwargs):
        super().execute(**kwargs)

        pathlib.Path(self.config.vectr.attire_log).write_text(json.dumps(self.attire_log, indent=4))
