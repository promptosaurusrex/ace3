import datetime
import logging
from typing import Optional

import pytz

from saq.collectors.hunter.correlation.registry import QuerySource
from saq.configuration.config import get_splunk_config


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

    def format_timespec_for_display(
        self,
        start_time: datetime.datetime,
        end_time: datetime.datetime,
    ) -> str:
        # Correlation queries currently execute against event time (SplunkClient
        # default `use_index_time=False`), so the display uses `earliest=/latest=`
        # rather than the index-time prefix. Timezone matches the original-query
        # rendering in saq/modules/splunk.py:fill_target_query_timespec so analysts
        # see one consistent TZ across the alert UI.
        tz = pytz.timezone(get_splunk_config(self.config_name).timezone)
        earliest = start_time.astimezone(tz).strftime("%m/%d/%Y:%H:%M:%S")
        latest = end_time.astimezone(tz).strftime("%m/%d/%Y:%H:%M:%S")
        return f"earliest={earliest} latest={latest}"
