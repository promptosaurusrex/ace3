from saq.collectors.hunter.correlation.registry import register_query_source


def register_default_sources():
    """Register the built-in query sources."""
    from saq.collectors.hunter.correlation.sources.splunk import SplunkQuerySource

    register_query_source("splunk", SplunkQuerySource())
