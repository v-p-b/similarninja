from binaryninja import *
from tarjan_sort import *
from spp_primes import *
from llil_categories import *


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