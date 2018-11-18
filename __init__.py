from binaryninja import *
from tarjan_sort import *
from spp_primes import *
from llil_categories import *
import json
import sys

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
class FuncInstructionFeatures(SPPFunctionProvider):
    @staticmethod
    def calculate(func):
        ret = 1
        for block in func.low_level_il:
            for ins in block:
                if ins.operation in LLIL_REDIRECT:
                    ret *= LLIL_FEATURE_REDIRECT
                elif ins.operation in LLIL_ARITHMETIC:
                    ret *= LLIL_FEATURE_ARITHMETIC
                elif ins.operation in LLIL_LOGIC:
                    ret *= LLIL_FEATURE_LOGIC
        return ret
        

class FuncStronglyConnectedFeatures(SPPFunctionProvider):
    @staticmethod
    def calculate(func):
        bb_relations = {}
        ret = 1
        for block in func.basic_blocks:
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
    def _primes(n):
        if n in ALL_PRIMES:
            return [n]
        # This is slow as hell for large numbers
        i = 0
        primes=[]
        while n != 1:
            if n % ALL_PRIMES[i] == 0:
                primes.append(ALL_PRIMES[i])
                n = n / ALL_PRIMES[i]
            else:
                i += 1
                if i >= len(ALL_PRIMES): 
                    log_error("Something is fucky with SPP primes! %x " % (n))
                    break
        return primes

    @staticmethod
    def _hcfnaive(a,b): 
        if(b==0): 
            return a 
        else: 
            return SPPFeatureProvider._hcfnaive(b,a%b) 

    @staticmethod
    def compare(f0,f1):
        if f0 == f1:
            return 1.0
        if f0 == 0 or f1 == 0:
            return 0.0 
        else:
            hcf = SPPFeatureProvider._hcfnaive(f0,f1)
            f0_hcf_primes=SPPFeatureProvider._primes(f0/hcf)
            f1_hcf_primes=SPPFeatureProvider._primes(f1/hcf)
            try:
                if len(f0_hcf_primes) > len(f1_hcf_primes):
                    return 1-(float(len(f0_hcf_primes))/len(SPPFeatureProvider._primes(f0)))
                else:
                    return 1-(float(len(f1_hcf_primes))/len(SPPFeatureProvider._primes(f1)))
            except OverflowError:
                return 0.0
            except ZeroDivisionError:
                log_error("Division by zero: %X %X HCF: %X Primes: %s %s " % (f0,f1,hcf,SPPFeatureProvider._primes(f0),SPPFeatureProvider._primes(f1)))
                raise

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
        #log_info("Final Value: %d" % value)
        return value

    @staticmethod
    def compare(f0,f1):
        binlen0=float(len(bin(f0)))
        binlen1=float(len(bin(f1)))
        hamming=float(bin(f0^f1).count('1'))
        if binlen0 >= binlen1:
            return 1.0-(hamming/binlen0)
        else:
            return 1.0-(hamming/binlen1)

class BBLCountProvider(FeatureProvider):
    def calculate(self, func):
        return len(func.basic_blocks)

    @staticmethod
    def compare(f0,f1):
        
        if f0>=f1:
            return 1-(float(f0-f1)/f0)
        else:
            return 1-(float(f1-f0)/f1)


SPP_PROVIDERS=[BBLTypeFeatures, BBLEdgeFeatures, FuncInstructionFeatures, FuncStronglyConnectedFeatures, FuncFlagsFeatures]

# PROVIDERS = [SPPFeatureProvider(SPP_PROVIDERS),DigraphFeatureProvider(), BBLCountProvider()]

PROVIDERS = [SPPFeatureProvider([BBLTypeFeatures]), SPPFeatureProvider([BBLEdgeFeatures]), SPPFeatureProvider([FuncInstructionFeatures]), SPPFeatureProvider([FuncStronglyConnectedFeatures, FuncFlagsFeatures]), DigraphFeatureProvider(),BBLCountProvider()]  

def gen_feature(bv):
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

def get_func_predecessors(bv,f):
    ret=[]
    for xref in bv.get_code_refs(f.start):
        x_func = xref.function
        low_level_il = x_func.get_low_level_il_at(bv.platform.arch, xred.address)
        il = function.low_level_il[low_level_il]
        if il.operation ==  LLIL_CALL: 
            ret.append(x_func.start)
    return ret

def match_fvs(data0, data1):
    res=[]
    ordered_keys0=sorted(data0,key=data0.get,reverse=True)
    ordered_keys1=sorted(data1,key=data1.get,reverse=True)

    for func0 in ordered_keys0: # So we can delete elements
        if func0 not in data0: continue
        feat0 = data0[func0]

        for func1 in ordered_keys1:
            if func1 not in data1: continue
            feat1 = data1[func1]
            matching=True
            for i in xrange(0,len(feat1)):
                if feat0[i] != feat1[i]:
                    matching=False
                    break
            if matching:
                log_info("%x <-> %x %s (%f)\n%s %s" % (long(func0), long(func1), [], 1.0, feat0, feat1))
                res.append(((long(func0), feat0), (long(func1),feat1), 1.0))
                del data0[func0]
                del data1[func1]
                break
    return res        

def compare_data(bv):
    f0=open(get_open_filename_input("filename0:","*"),"r")
    f1=open(get_open_filename_input("filename1:","*"),"r")
    #f0=open("/tmp/1291.json","r")
    #f1=open("/tmp/1292.json","r")
    data0=json.loads(f0.read())
    data1=json.loads(f1.read())
    log_info("Data sizes: %d %d" % (len(data0), len(data1)))
    matches=match_fvs(data0, data1)
    log_info("Data sizes after matching: %d %d" % (len(data0), len(data1)))
    # return
    # Inexact matches
    for func0 in list(data0.keys()): # So we can delete elements
        if func0 not in data0: continue
        feat0 = data0[func0]

        sims0 = [None] * len(PROVIDERS)
        sim_avg0=0.0
        func_match=None
        feat_match=None
        for func1 in list(data1.keys()):
            if func1 not in data1: continue
            feat1 = data1[func1]

            sims = [None] * len(PROVIDERS)
            for i, p in enumerate(PROVIDERS):
                sims[i]=p.compare(feat0[i],feat1[i])
            sim_avg=0.0
            for s in sims:
                sim_avg += s
            sim_avg = sim_avg / len(sims)        

            if sim_avg > sim_avg0:
                sim_avg0=sim_avg
                sims0=sims
                func_match=func1
                feat_match=feat1
            if sim_avg0 == 1.0: break # Exit early for perfect matches
        
        log_info("%x <-> %x %s (%f)\n%s %s" % (long(func0), long(func_match), repr(sims0), sim_avg0, feat0, feat_match))
        matches.append(((long(func0), feat0), (long(func_match),feat_match), sim_avg0))
        del data0[func0]
        del data1[func_match]
    out = open(get_save_filename_input("Filename to save comparison results:","json","compare.json"),"wb")
    out.write(json.dumps(matches))
    out.close()


PluginCommand.register("SimilarNinja - Generate Feature Vectors", "Generates Feature Vectors for all functions", gen_feature)
PluginCommand.register("SimilarNinja - Compare", "Generates functions from generated data files", compare_data)
