import importlib
import logging

from saq.collectors.hunter.correlation.registry import clear_query_sources, register_query_source
from saq.configuration import get_config

_loaded = False
def load_query_sources_from_config(force: bool = False):
    """instantiate and register all query sources declared under hunter.correlation.query_sources"""
    global _loaded
    if _loaded and not force:
        return

    clear_query_sources()

    hunter_cfg = getattr(get_config(), "hunter", None)
    correlation = getattr(hunter_cfg, "correlation", None) if hunter_cfg else None
    if not correlation:
        _loaded = True
        return

    for source_config in correlation.query_sources:
        try:
            module = importlib.import_module(source_config.python_module)
            cls = getattr(module, source_config.python_class)
            register_query_source(source_config.name, cls(**source_config.kwargs))
        except Exception:
            logging.error(
                "failed to load query source %s (%s.%s)",
                source_config.name,
                source_config.python_module,
                source_config.python_class,
                exc_info=True,
            )

    _loaded = True


def reset_query_sources_loaded_flag():
    """test helper: force the next load_query_sources_from_config() call to reload"""
    global _loaded
    _loaded = False