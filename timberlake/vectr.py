from gql import Client
from gql.transport.requests import RequestsHTTPTransport
from gql.transport.requests import log as gql_logger
from gql.dsl import *
from contextlib import contextmanager
import logging

from .types import VectrConfig, Union, VectrObject, VectrTestCase
from .settings import global_settings
from .common import deep_get

# don't verify connections in debug mode and suppress insecure warnings
verify = True
if global_settings.debug:
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    verify = False

# disable builtin logger used by gql library as it will write to the output log file
gql_logger.setLevel(logging.WARNING)


class VectrGraphQLClient:
    def __init__(self, config: VectrConfig):
        self._config = config
        self.url: str = self._config.host + global_settings.graphql_uri

        self._transport = RequestsHTTPTransport(
            url=self.url,
            headers={
                "Authorization": f"VEC1 {self._config.api_credentials.access_key}:{self._config.api_credentials.secret_key}"
            },
            verify=verify,
        )
        self.client = Client(transport=self._transport, fetch_schema_from_transport=True)
        with self.session():
            self.schema = DSLSchema(self.client.schema)

    @contextmanager
    def session(self):
        session = self.client.connect_sync()
        try:
            yield session
        finally:
            self.client.close_sync()

    def dsl_query(self, query: Union[DSLQuery, DSLMutation]) -> dict:
        with self.session() as session:
            results = session.execute(dsl_gql(query))
        return results


#
# GraphQL DSL functions below
#


def get_phase_by_name(client: VectrGraphQLClient, phase_name: str) -> VectrObject:
    query = DSLQuery(
        client.schema.Query.phases(filter={"name": {"eq": phase_name}}).select(
            client.schema.PhaseConnection.nodes.select(
                client.schema.Phase.name,
                client.schema.Phase.id,
            )
        )
    )
    results = client.dsl_query(query=query)
    # results = {'phases': {'nodes': [{'name': 'name', 'id': '<guid>'}]}}
    phase: dict = deep_get(results, ["phases", "nodes"])[0]
    return VectrObject(**phase)


def get_assessment_by_name(
    client: VectrGraphQLClient, assessment_name: str, database_name: str
) -> Union[VectrObject, None]:
    query = DSLQuery(
        client.schema.Query.assessments(filter={"name": {"eq": assessment_name}}, db=database_name).select(
            client.schema.AssessmentConnection.nodes.select(
                client.schema.Assessment.name,
                client.schema.Assessment.id,
            )
        )
    )
    results = client.dsl_query(query=query)
    # results ={'assessments': {'nodes': [{'name': 'name', 'id': '<guid>'}]}}
    nodes = deep_get(results, ["assessments", "nodes"])
    if len(nodes) > 0:
        assessment: dict = nodes[0]
        return VectrObject(**assessment)
    else:
        return


def get_campaign_by_name(
    client: VectrGraphQLClient, campaign_name: str, database_name: str
) -> Union[VectrObject, None]:
    query = DSLQuery(
        client.schema.Query.campaigns(filter={"name": {"eq": campaign_name}}, db=database_name).select(
            client.schema.CampaignConnection.nodes.select(
                client.schema.Campaign.name,
                client.schema.Campaign.id,
            )
        )
    )
    results = client.dsl_query(query=query)
    # results ={'assessments': {'nodes': [{'name': 'name', 'id': '<guid>'}]}}
    nodes = deep_get(results, ["campaigns", "nodes"])
    if len(nodes) > 0:
        campaign: dict = nodes[0]
        return VectrObject(**campaign)
    else:
        return


def create_assessment_group(client: VectrGraphQLClient, assessment_name: str, database_name: str) -> VectrObject:
    # TODO: check for existing assessments of the provided name
    mut_input = {
        "db": database_name,
        "assessmentData": [{"name": assessment_name, "organizationIds": [global_settings.org_id]}],
    }
    mut = DSLMutation(
        client.schema.Mutation.assessment.select(
            client.schema.AssessmentMutations.create.args(input=mut_input).select(
                client.schema.CreateAssessmentPayload.assessments.select(
                    client.schema.Assessment.name, client.schema.Assessment.id
                )
            )
        )
    )
    results = client.dsl_query(query=mut)
    # results = {'assessment': {'create': {'assessments': [{'name': 'name', 'id': '<guid>'}]}}}
    assessment: dict = deep_get(results, ["assessment", "create", "assessments"])[0]
    return VectrObject(**assessment)


def create_campaign_in_assessment(
    client: VectrGraphQLClient, database_name: str, assessment_id: str, campaign_name
) -> VectrObject:
    # TODO: check for existing campaigns of the provided name
    mut_input = {
        "db": database_name,
        "assessmentId": assessment_id,
        "campaignData": [{"name": campaign_name, "organizationIds": [global_settings.org_id]}],
    }
    mut = DSLMutation(
        client.schema.Mutation.campaign.select(
            client.schema.CampaignMutations.create.args(input=mut_input).select(
                client.schema.CreateCampaignPayload.campaigns.select(
                    client.schema.Campaign.name, client.schema.Campaign.id
                )
            )
        )
    )
    results = client.dsl_query(query=mut)
    # {'campaign': {'create': {'campaigns': [{'name': 'name', 'id': '<guid>'}]}}}
    campaign: dict = deep_get(results, ["campaign", "create", "campaigns"])[0]
    return VectrObject(**campaign)


def create_testcase_in_campaign(
    client: VectrGraphQLClient, database: str, campaign_id: str, test_case: VectrTestCase
) -> VectrObject:
    mut_input = {"db": database, "campaignId": campaign_id, "testCaseData": [test_case.__dict__]}
    mut = DSLMutation(
        client.schema.Mutation.testCase.select(
            client.schema.TestCaseMutations.createWithoutTemplate.args(input=mut_input).select(
                client.schema.CreateTestCasePayload.testCases.select(
                    client.schema.TestCase.name, client.schema.TestCase.id
                )
            )
        )
    )
    results = client.dsl_query(query=mut)
    # {'testCase': {'createWithoutTemplate': {'testCases': [{'name': 'name', 'id': '<guid>'}]}}}
    tc: dict = deep_get(results, ["testCase", "createWithoutTemplate", "testCases"])[0]
    return VectrObject(**tc)


def upsert_assessment_by_name(client: VectrGraphQLClient, assessment_name: str, database_name: str):
    assessment = get_assessment_by_name(client=client, assessment_name=assessment_name, database_name=database_name)
    if assessment is None:
        assessment = create_assessment_group(
            client=client, assessment_name=assessment_name, database_name=database_name
        )
    return assessment


def upsert_campaign_by_name(client: VectrGraphQLClient, campaign_name: str, database_name: str, asessment_id: str):
    campaign = get_campaign_by_name(client=client, campaign_name=campaign_name, database_name=database_name)
    if campaign is None:
        campaign = create_campaign_in_assessment(
            client=client, campaign_name=campaign_name, database_name=database_name, assessment_id=asessment_id
        )
    return campaign
