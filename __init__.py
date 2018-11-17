from binaryninja import *
from tarjan_sort import *
import sys
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

LLIL_CALLS = [ LowLevelILOperation.LLIL_CALL,
               LowLevelILOperation.LLIL_CALL_OUTPUT_SSA,
               LowLevelILOperation.LLIL_CALL_PARAM,
               LowLevelILOperation.LLIL_CALL_SSA,
               LowLevelILOperation.LLIL_CALL_STACK_ADJUST,
               LowLevelILOperation.LLIL_CALL_STACK_SSA,
             ]

def bbl_type(b):
    if len(b.incoming_edges) == 0:
        return NODE_ENTRY
    if len(b.outgoing_edges) == 0:
        return NODE_EXIT
    return NODE_NORMAL

def bbl_edges(b):
    ins = b.incoming_edges
    outs = b.outgoing_edges
    ret = 1

    for e in outs:
        ret *= EDGE_OUT_CONDITIONAL
    for e in ins:
        ret *= EDGE_IN_CONDITIONAL

    return ret

def bbl_instruction_features(b):
    # [TODO] Binary Ninja API for instruction classification
    return 1

def gen_spp(bv):
    results={}
    for func in bv.functions:
        results[func.start] = 1
        bb_relations = {}
        for block in func.low_level_il:
            results[func.start]*=bbl_type(block)
            results[func.start]*=bbl_edges(block)
            results[func.start]*=bbl_instruction_features(block)

            # Creating bb_relations 
            bb_relations[block.start] = []
            for e in block.outgoing_edges:
                bb_relations[block.start].append(e.target.start)

            for e in block.incoming_edges:
                try:
                    bb_relations[e.source.start].append(block.start)
                except KeyError:
                    bb_relations[e.source.start] = [block.start]
        # log_info(repr(bb_relations))
        # Extracting function level features 
        try:
            strongly_connected = strongly_connected_components(bb_relations)
            for sc in strongly_connected:
                if len(sc) > 1:
                    results[func.start] *= FEATURE_LOOP
                else:
                    if sc[0] in bb_relations and sc[0] in bb_relations[sc[0]]:
                        results[func.start] *= FEATURE_LOOP
            results[func.start] *= FEATURE_STRONGLY_CONNECTED ^ len(strongly_connected)
        except:
            log_error("Exception: %s" % (sys.exc_info()[1]))
    log_info(repr(results))

PluginCommand.register("SimilarNinja - Generate SPPs", "Generates SPP hashes for all functions", gen_spp)
