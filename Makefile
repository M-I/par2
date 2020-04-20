PROJECT = par2
PROJECT_DESCRIPTION = An erlang convenience wrapper around the Par2 utility
PROJECT_VERSION = 0.1.0

EUNIT_OPTS = verbose

EDOC_OPTS = {dir, docs}

include erlang.mk

docs:: edoc
