# Migration Notes

Configuration changes existing production systems must make when upgrading. Each
entry notes whether it is a **required** (breaking) change or optional.

## Detection point signature attribution (git commit tracking)

Detection points now carry signature attribution (`signature_uuid` +
`signature_version`). For the rule-driven signature families (YARA,
observable_modifier rules, hunts), `signature_version` is the git commit hash of
the repository the rules were loaded from. Two of those families need config
changes to enable that tracking.

In production these signature families are commonly stored in **separate git
repositories**, and the directory ACE *loads* rules from is not necessarily the
git checkout. Attribution is therefore driven by an explicit `git_dir` the
operator configures. Shared validation rule: **`git_dir` must equal or be an
ancestor of the rule directory** (the repo must actually contain the rules). A
`git_dir` that does not contain the rules is a logged error and falls back to the
version `"unknown"` — it is never fatal. Omitting `git_dir` entirely also yields
`"unknown"` (git tracking simply disabled).

### 1. Hunts — `hunt_types[].rule_dirs` (REQUIRED / breaking)

`rule_dirs` changed from a list of strings to a list of `{rule_dir, git_dir?}`
mappings. **Bare strings no longer load — config validation fails until every
entry is converted to the mapping form.** Keep the `rule_dir:` key even when you
omit `git_dir`.

```yaml
# before
hunt_type_splunk:
  rule_dirs:
    - signatures/hunts/splunk

# after (with git tracking)
hunt_type_splunk:
  rule_dirs:
    - rule_dir: signatures/hunts/splunk
      git_dir: signatures        # must equal or contain rule_dir

# after (git tracking disabled — version recorded as "unknown")
hunt_type_splunk:
  rule_dirs:
    - rule_dir: signatures/hunts/splunk
```

The shipped `etc/saq.splunk.default.yaml` has already been migrated to the new
form as part of this change.

### 2. observable_modifier — new optional `git_dir` (non-breaking)

Add `git_dir` to the observable_modifier module config alongside
`rules_config_path`. Omitting it leaves attribution at `"unknown"` and does not
change any existing behavior.

```yaml
# observable_modifier module section (e.g. etc/saq.yaml)
<observable_modifier module section>:
  rules_config_path: signatures/analyst_data/observable_modifier_rules.yaml
  git_dir: signatures            # new — must equal or contain the rules file's directory
```

### 3. YARA — no config change

YARA commit attribution is resolved by the `yara_scanner` library (each match
result carries a `commit` key), so no ACE-side configuration is required. If the
installed `yara_scanner` predates that feature, the version is simply recorded as
`"unknown"`.
