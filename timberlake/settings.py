from pydantic import BaseSettings, Field


class GlobalSettings(BaseSettings):
    debug: bool = Field(default=False, env="TIMBERLAKE_DEBUG")
    log_file: str = Field(default=".timberlake.log", env="TIMBERLAKE_LOGFILE")
    # default VECTR org id for "Security Risk Advisors"
    org_id: str = Field(default="1cf413ba-326a-4d18-979c-367eb1306f69", env="TIMBERLAKE_VECTR_ORGID")
    graphql_uri: str = Field(default="/sra-purpletools-rest/graphql", env="TIMBERLAKE_VECTR_GQLURI")


global_settings = GlobalSettings()
