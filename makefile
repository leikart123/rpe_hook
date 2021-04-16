MODULES = rpe_hook

PGFILEDESC = "rpe_hook"

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)