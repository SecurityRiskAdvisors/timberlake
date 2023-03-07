from dataclasses import dataclass, field
import glob

from .types import List, VectrConfig, TestCaseLocation
from .common import FileLoaderMixin
from .testcase import TestCase


@dataclass
class TimberlakeConfig(FileLoaderMixin):
    testcases: TestCaseLocation
    vectr: VectrConfig
    profiles: List[str] = field(default_factory=lambda: ["default"])

    def _collect_testcases(self):
        """recursively get all YAML (.yml) files from the test case directory and create TestCase objects for them"""
        yaml_files = glob.glob(f"{self.testcases.directory}/*.yml", recursive=self.testcases.recurse)
        self.test_case_list = [TestCase.from_file(path=yaml_file) for yaml_file in yaml_files]

    def _set_testcase_profiles(self):
        """copy the credential profiles names from the parent test case to each step in the test case"""
        for tc in self.test_case_list:
            for block in tc.steps:
                block.block.profiles = self.profiles

    def __post_init__(self):
        self.test_case_list: List[TestCase] = []
        # remove ending slash from directory
        if self.testcases.directory[:-1] == "/":
            self.testcases.directory = self.testcases.directory[: len(self.testcases.directory) - 1]

        self._collect_testcases()
        self._set_testcase_profiles()
