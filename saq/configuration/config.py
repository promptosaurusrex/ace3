import sys
from typing import TYPE_CHECKING, Optional, Type

from pydantic import BaseModel

from saq.configuration.loader import load_configuration
from saq.configuration.schema import ACEConfig
from saq.constants import DB_ACE, SERVICE_ENGINE

if TYPE_CHECKING:
    from saq.engine.core import EngineServiceConfig
    from saq.modules.config import AnalysisModuleConfig
    from saq.configuration.schema import ServiceConfig, SplunkConfig, ProxyConfig, DatabaseConfig

# parsed and validated configuration
CONFIG: Optional[ACEConfig] = None

# registered integration configurations
REGISTERED_INTEGRATION_CONFIGURATIONS: dict[str, Type[BaseModel]] = {}

# integration configurations
INTEGRATION_CONFIGURATIONS: dict[str, BaseModel] = {}

def get_config(name: Optional[str] = None) -> ACEConfig:
    """Returns the global configuration object (YAMLConfig)."""
    if name is None:
        return CONFIG

    try:
        return INTEGRATION_CONFIGURATIONS[name]
    except KeyError:
        raise KeyError(f"integration configuration for {name} not found")

def get_database_config(name: str=DB_ACE) -> "DatabaseConfig":
    return get_config().get_database_config(name)

def get_engine_config() -> "EngineServiceConfig":
    return get_config().get_service_config(SERVICE_ENGINE)

def get_analysis_module_config(name: str) -> "AnalysisModuleConfig":
    return get_config().get_analysis_module_config(name)

def get_service_config(name: str) -> "ServiceConfig":
    return get_config().get_service_config(name)

def get_splunk_config(name: str = "default") -> "SplunkConfig":
    return get_config().get_splunk_config(name)

def get_proxy_config(name: Optional[str] = None) -> "ProxyConfig":
    return get_config().get_proxy_config(name)

def set_config(config):
    global CONFIG
    CONFIG = config

def resolve_configuration(existing_config: ACEConfig):
    global CONFIG
    existing_config.resolve_all_values()
    CONFIG = ACEConfig.model_validate(existing_config.raw._data)
    CONFIG.raw = existing_config.raw

    # load integration configurations as separate objects
    for integration_name, integration_class in REGISTERED_INTEGRATION_CONFIGURATIONS.items():
        INTEGRATION_CONFIGURATIONS[integration_name] = integration_class.model_validate(existing_config.raw._data)

def register_integration_configuration(integration_name: str, integration_class: Type[BaseModel]):
    if integration_name in REGISTERED_INTEGRATION_CONFIGURATIONS:
        raise ValueError(f"integration configuration for {integration_name} already registered")

    REGISTERED_INTEGRATION_CONFIGURATIONS[integration_name] = integration_class

def initialize_configuration(config_paths: Optional[list[str]]=None):
    global CONFIG

    # load configuration files
    if config_paths is None:
        config_paths = []
    
    try:
        raw_config = load_configuration(config_paths=config_paths)
        CONFIG = ACEConfig.model_validate(raw_config._data)
        CONFIG.raw = raw_config
    except Exception as e:
        sys.stderr.write(f"ERROR: unable to load configuration: {e}")
        raise
