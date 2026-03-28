import datetime
import logging
from typing import Optional

from saq.collectors.hunter.correlation.registry import QuerySource


class SplunkQuerySource(QuerySource):
    """Query source adapter for Splunk, wrapping the existing Splunk client."""

    def __init__(self, config_name: str = "default"):
        self.config_name = config_name

    def execute_query(
        self,
        query: str,
        start_time: datetime.datetime,
        end_time: datetime.datetime,
        timeout: datetime.timedelta,
    ) -> list[dict]:
        from saq.splunk import SplunkQueryObject

        logging.debug("executing splunk query via correlation source %s", self.config_name)

        splunk_query = SplunkQueryObject(
            uri=query,
            start_time=start_time,
            end_time=end_time,
            max_result_count=0,
            query_timeout=timeout,
        )

        splunk_query.execute()
        return splunk_query.json() or []
