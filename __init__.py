from binaryninja import *
from tarjan_sort import *
import json
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

# End of Diaphora prime constants

LLIL_CALLS = [ LowLevelILOperation.LLIL_CALL,
               LowLevelILOperation.LLIL_CALL_OUTPUT_SSA,
               LowLevelILOperation.LLIL_CALL_PARAM,
               LowLevelILOperation.LLIL_CALL_SSA,
               LowLevelILOperation.LLIL_CALL_STACK_ADJUST,
               LowLevelILOperation.LLIL_CALL_STACK_SSA,
             ]


class SPPBBLProvider:
    @staticmethod
    def calculate(bbl):
        pass

class SPPFunctionProvider:
    @staticmethod
    def calculate(func):
        pass

class BBLTypeFeatures(SPPBBLProvider):
    @staticmethod
    def calculate(b):
        ret = 1
        
        if len(b.incoming_edges) == 0:
            ret *= NODE_ENTRY
        if len(b.outgoing_edges) == 0:
            ret *= NODE_EXIT
        ret *= NODE_NORMAL
        return ret

class BBLEdgeFeatures(SPPBBLProvider):
    @staticmethod
    def calculate(b):
        ret = 1
        
        ins = b.incoming_edges
        outs = b.outgoing_edges
            
        for e in outs:
            ret *= EDGE_OUT_CONDITIONAL
        for e in ins:
            ret *= EDGE_IN_CONDITIONAL

        return ret
class BBLInstructionFeatures(SPPBBLProvider):
    @staticmethod
    def calculate(b):
        # [TODO] Binary Ninja API for instruction classification
        return 1

class FuncStronglyConnectedFeatures(SPPFunctionProvider):
    @staticmethod
    def calculate(func):
        bb_relations = {}
        ret = 1
        for block in func.low_level_il:
            # Creating bb_relations 
            bb_relations[block.start] = []
            for e in block.outgoing_edges:
                bb_relations[block.start].append(e.target.start)

            for e in block.incoming_edges:
                try:
                    bb_relations[e.source.start].append(block.start)
                except KeyError:
                    bb_relations[e.source.start] = [block.start]
        try:
            strongly_connected = strongly_connected_components(bb_relations)
            for sc in strongly_connected:
                if len(sc) > 1:
                    ret *= FEATURE_LOOP
                else:
                    if sc[0] in bb_relations and sc[0] in bb_relations[sc[0]]:
                        ret *= FEATURE_LOOP
            ret *= FEATURE_STRONGLY_CONNECTED ** len(strongly_connected)
        except:
            log_error("Exception: %s" % (sys.exc_info()[1]))
        return ret



class FuncFlagsFeatures(SPPFunctionProvider):
    @staticmethod
    def calculate(func):
        ret = 1    
        if not func.can_return:
            ret *= FEATURE_FUNC_NO_RET
        if func.symbol.type is SymbolType.ImportedFunctionSymbol:
            ret *= FEATURE_FUNC_LIB
        # [TODO] Binary Ninja API for Thunks
        return ret

class FeatureProvider:
    def calculate(self, func):
        pass

    @staticmethod
    def compare(f0, f1):
        pass

class SPPFeatureProvider(FeatureProvider):
    def __init__(self, features=[]):
        self.features=features

    def calculate(self, func):
        ret=1
        for p in self.features:
            for block in func.basic_blocks:
                if issubclass(p,SPPBBLProvider):
                    ret *= p.calculate(block)    
            if issubclass(p,SPPFunctionProvider):
                ret *= p.calculate(func)
        return ret

    @staticmethod
    def compare(f0,f1):
        if f0 == f1:
            return 1.0
        else:
            return 0.5

class DigraphFeatureProvider(FeatureProvider):
    def __init__(self):
        self.visited=set()

    def dfs(self,block,value):
        #log_info("Entering %x value: %x" % (block.start,value))
        
        if block.start not in self.visited:  
            value *= 2    
            value += 1
            #log_info("Not visited yet! %x" % (value))
            self.visited.add(block.start)
        else:
            return value

        for e in block.outgoing_edges:
            value=self.dfs(e.target, value)
        value *= 2
        #log_info("Leaving %x Value: %x" % (block.start,value))       
        return value

    def calculate(self,func):
        block=func.get_basic_block_at(func.start)
        
        value=self.dfs(block, 0)
        log_info("Final Value: %d" % value)
        return value

class BBLCountProvider(FeatureProvider):
    def calculate(self, func):
        return len(func.basic_blocks)

SPP_PROVIDERS=[BBLTypeFeatures, BBLEdgeFeatures, BBLInstructionFeatures, FuncStronglyConnectedFeatures, FuncFlagsFeatures]

PROVIDERS = [SPPFeatureProvider(SPP_PROVIDERS),DigraphFeatureProvider(), BBLCountProvider()]

def gen_spp(bv):
    results={}
    for func in bv.functions:
        idx=long(func.start)
        results[idx] = [None] * len(PROVIDERS)
        for i,p in enumerate(PROVIDERS):
            results[idx][i] = p.calculate(func)
        
    log_info(repr(results))
    out = open(get_save_filename_input("Filename to save function hashes:","json","output.json"),"wb")
    out.write(json.dumps(results))
    out.close()

PluginCommand.register("SimilarNinja - Generate Feature Vectors", "Generates Feature Vectors for all functions", gen_spp)
