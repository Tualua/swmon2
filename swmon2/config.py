from pydantic import BaseSettings


class Settings(BaseSettings):
    app_name: str = "Switch Monitor"
    kea_ipaddr = '172.17.17.254'
    kea_api_port = 8000
    snmp_community = 'public'


settings = Settings()
