import datetime
import logging
from typing import Optional

from saq.collectors.hunter.correlation.registry import QuerySource


class SplunkQuerySource(QuerySource):
    """Query source adapter for Splunk, wrapping the existing Splunk client."""

    default_time_field = "_time"
    default_time_format = "iso8601"

    def __init__(self, config_name: str = "default"):
        self.config_name = config_name

    def execute_query(
        self,
        query: str,
        start_time: datetime.datetime,
        end_time: datetime.datetime,
        timeout: datetime.timedelta,
        source_options: Optional[dict] = None,
    ) -> list[dict]:
        from saq.splunk import SplunkClient

        logging.debug("executing splunk query via correlation source %s", self.config_name)

        client = SplunkClient(self.config_name)
        return client.query(
            query=query,
            start=start_time,
            end=end_time,
            timeout=timeout,
        )
