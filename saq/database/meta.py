from sqlalchemy.orm import declarative_base

# metadata for tables in the main ace database -- this is what alembic
# autogenerate targets
Base = declarative_base()

# separate metadata for tables that live in the dedicated analysis-result-cache
# database. kept out of Base so alembic (which manages only the ace database)
# never tries to create or drop them there
CacheBase = declarative_base()
