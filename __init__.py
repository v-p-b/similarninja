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

class FeatureProvider:
    def calculate(self, func):
        pass

    @staticmethod
    def compare(f0, f1):
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

class StringHistogramProvider(FeatureProvider):
    def __init__(self):
        self.cache=None


    def calculate(self, func):
        # String info is available for the global BinaryView
        # String histograms are calculated and cached at first call
        if self.cache is None:
            self.cache = {}
            vectors = {}
            bv=func.view
            for s in bv.strings:
                value = s.value
                str_xrefs = bv.get_code_refs(s.start)
                #log_info("--------- %s" % s.value)

                # Updating character counts for all functions referencing the current string
                for x in str_xrefs:
                    if x.function.start not in vectors:
                        vectors[x.function.start] = [0]*256
                    for c in s.value:
                        vectors[x.function.start][ord(c)] += 1
                    #log_info(repr(vectors[x.function.start]))
            for f, c_vec in vectors.iteritems():
                #log_info("%s" % repr(c_vec))
                self.cache[f] = 0
                cmax = 0
                begin = 0
                started = False
                end = 255

                # Find maximum and cut empty ends
                for i in xrange(0,256):
                    if c_vec[i] != 0:
                        if not started:
                            begin = i
                            started = True
                        end = i
                    if c_vec[i] > cmax:
                        cmax = c_vec[i]
                #log_info("%d %d %s" % (begin,end,repr(c_vec[begin:end+1])))

                # Normalize charcter counts to 0-15 and encode vector as integer
                # [4,0,8,0,16,8,4,2] -> 0x3070f731
                for i in xrange(begin, end):
                    self.cache[f] *= 16
                    self.cache[f] += int((float(c_vec[i])/cmax)*15)
                #log_info("%X" % self.cache[f])
        if func.start in self.cache:
            return self.cache[func.start]
        else:
            return 0

    @staticmethod
    def compare(f0,f1):
        binlen0=float(len(bin(f0)))
        binlen1=float(len(bin(f1)))
        hamming=float(bin(f0^f1).count('1'))
        if binlen0 >= binlen1:
            return 1.0-(hamming/binlen0)
        else:
            return 1.0-(hamming/binlen1)

SPP_PROVIDERS=[BBLTypeFeatures, BBLEdgeFeatures, FuncInstructionFeatures, FuncStronglyConnectedFeatures, FuncFlagsFeatures]

# PROVIDERS = [SPPFeatureProvider(SPP_PROVIDERS),DigraphFeatureProvider(), BBLCountProvider()]

PROVIDERS = [SPPFeatureProvider([BBLTypeFeatures]), SPPFeatureProvider([BBLEdgeFeatures]), SPPFeatureProvider([FuncInstructionFeatures]), SPPFeatureProvider([FuncStronglyConnectedFeatures, FuncFlagsFeatures]), DigraphFeatureProvider(),StringHistogramProvider()]  

def gen_feature(bv):
    results={}
    for func in bv.functions:
        idx=long(func.start)
        results[idx] = [None] * len(PROVIDERS)
        for i,p in enumerate(PROVIDERS):
            results[idx][i] = p.calculate(func)
    log_info(repr(results))
    if show_message_box("SimilarNinja","Do you want to save the results to the Binary Ninja database?", MessageBoxButtonSet.YesNoButtonSet, MessageBoxIcon.QuestionIcon) == 1:
        # Storing as JSON is wasteful, but more secure than Pickle... good enough for now
        bv.store_metadata("similarninja",json.dumps(results))
    else:
        out = open(get_save_filename_input("Filename to save function hashes:","*","output.json"),"wb")
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


class SimilarNinjaComparer(BackgroundTaskThread):
    def __init__(self, text=""):
        super(SimilarNinjaComparer, self).__init__(text, False)


    def match_fvs(self, data0, data1):
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


    def run(self):        
        self.progress="Opening files for comparison"

        fn0 = get_open_filename_input("filename0:","*")
        fn1 = get_open_filename_input("filename1:","*")

        data0 = None
        data1 = None
        
        if fn0.endswith(".bndb"):
            fm = FileMetadata()
            db0 = fm.open_existing_database(fn0)
            for t in db0.available_view_types:
                try:
                    bv0= db0.get_view_of_type(t.name)
                    data0 = json.loads(bv0.query_metadata("similarninja"))
                    break
                except KeyError:
                    pass
        else:
            f0 = open(fn0, "r")
            data0=json.loads(f0.read())
        
        if fn1.endswith(".bndb"):
            fm = FileMetadata()
            db1 = fm.open_existing_database(fn1)
            for t in db1.available_view_types:
                try:
                    bv1 = db1.get_view_of_type(t.name)
                    data1 = json.loads(bv1.query_metadata("similarninja"))
                    break
                except KeyError:
                    pass
        else:
            f1 = open(fn1, "r")
            data1=json.loads(f1.read())

        self.progress="Comparing..."

        log_info("Data sizes: %d %d" % (len(data0), len(data1)))
        matches=self.match_fvs(data0, data1)
        log_info("Data sizes after matching: %d %d" % (len(data0), len(data1)))
        
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
        self.finish()
        out = open(get_save_filename_input("Filename to save comparison results:","*","compare.json"),"wb")
        out.write(json.dumps(matches))
        out.close()
        return matches

def tester(bv0,bv1,result_file):
    matches=json.loads(open(result_file,"r").read())
    unknown=0
    success=0
    failure=0
    for m in matches:
        func0=bv0.get_function_at(m[0][0])
        if func0 is None or func0.start != m[0][0]:
            log_info("Switching views")
            bv1, bv0 = bv0, bv1
            func0=bv0.get_function_at(m[0][0])
        func1=bv1.get_function_at(m[1][0])
        try:
            if func0.name.startswith("sub_") and func1.name.startswith("sub_"):
                unknown += 1
                continue
        except AttributeError:
            log_error("Function not found: %x %x" % (m[0][0],m[1][0]))
            return
        if func0.name == func1.name:
            log_info("%s (%x) == %s (%x)" % (func0.name, func0.start, func1.name, func1.start))
            success += 1
        else:
            log_info("%s (%x) != %s (%x)" % (func0.name, func0.start, func1.name, func1.start))
            failure += 1
    log_info("Success: %d" % success)
    log_info("Failure: %d" % failure)
    log_info("Total: %d (%d <-> %d) " % (len(matches), len(bv0.functions), len(bv1.functions)))

def compare(bv):
    sn_comparer=SimilarNinjaComparer()
    sn_comparer.start()

PluginCommand.register("SimilarNinja - Generate Feature Vectors", "Generates Feature Vectors for all functions", gen_feature)
PluginCommand.register("SimilarNinja - Compare", "Compare functions based on generated data files", compare)
