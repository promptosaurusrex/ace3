# Continuous polling subsystem that asks external systems whether they
# have autonomously remediated an observable.
#
# Companion to ``saq/remediation/`` (where ACE *initiates* the action) and
# modeled on ``saq/file_collection/`` (per-row exponential backoff, UUID
# locking, deadline). Generic in core ACE; vendor probe classes live in
# integration repos and are wired in via YAML.
