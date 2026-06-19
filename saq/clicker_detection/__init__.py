# vim: sw=4:ts=4:et:cc=120

"""Clicker detection subsystem.

Answers the analyst question "did anyone click this URL or visit this domain?" by
running per-source log searches (Splunk first, others later) and aggregating any
matches into a unified, source-agnostic "URL Clicks" view on the alert page.

- ``config``: loads the analyst-editable search config (which query each source runs
  per observable type) and builds source search URLs.
- ``timeline``: the ``ClickerEvent`` record, the provider protocol an Analysis
  implements to publish clicks, and ``gather_clicker_events()`` which the alert UI
  uses to collect them across all sources.
"""
