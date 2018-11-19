# Prime constants from Diaphora: https://github.com/joxeankoret/diaphora/blob/master/jkutils/graph_hashes.py

#-------------------------------------------------------------------------------
# Different type of basic blocks (graph nodes).
NODE_ENTRY = 2
NODE_EXIT = 3
NODE_NORMAL = 5

#
# NOTE: In the current implementation (Nov-2018) all edges are considered as if
# they were conditional. Keep reading...
#
EDGE_IN_CONDITIONAL = 7
EDGE_OUT_CONDITIONAL = 11

#
# Reserved but unused because, probably, it doesn't make sense when comparing
# multiple different architectures.
#
EDGE_IN_UNCONDITIONAL = 13
EDGE_OUT_UNCONDITIONAL = 17

# 
# The following are feature types that aren't applied at basic block but rather
# at function level. The idea is that if we do at function level we will have no
# problems finding the same function that was re-ordered because of some crazy
# code a different compiler decided to create (i.e., resilient to reordering).
#
FEATURE_LOOP = 19
FEATURE_CALL = 23
FEATURE_DATA_REFS = 29
FEATURE_CALL_REF = 31
FEATURE_STRONGLY_CONNECTED = 37
FEATURE_FUNC_NO_RET = 41
FEATURE_FUNC_LIB = 43
FEATURE_FUNC_THUNK = 47 

# End of Diaphora prime constants

LLIL_FEATURE_REDIRECT = 53 
LLIL_FEATURE_ARITHMETIC = 59
LLIL_FEATURE_LOGIC = 61

ALL_PRIMES = [
				NODE_ENTRY,
				NODE_EXIT,
				NODE_NORMAL,
				EDGE_IN_CONDITIONAL,
				EDGE_OUT_CONDITIONAL,
				EDGE_IN_UNCONDITIONAL,
				EDGE_OUT_UNCONDITIONAL,
				FEATURE_LOOP,
				FEATURE_CALL,
				FEATURE_DATA_REFS,
				FEATURE_CALL_REF,
				FEATURE_STRONGLY_CONNECTED,
				FEATURE_FUNC_NO_RET,
				FEATURE_FUNC_LIB,
				FEATURE_FUNC_THUNK,
                LLIL_FEATURE_REDIRECT,
                LLIL_FEATURE_ARITHMETIC,
                LLIL_FEATURE_LOGIC,
			]