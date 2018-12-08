from binaryninja import *
from providers import *
import json

PROVIDERS = [SPPFeatureProvider([BBLTypeFeatures]), SPPFeatureProvider([BBLEdgeFeatures]), SPPFeatureProvider([FuncInstructionFeatures]), SPPFeatureProvider([FuncStronglyConnectedFeatures, FuncFlagsFeatures]), DigraphFeatureProvider(),(StringHistogramProvider(), 2.0)]  

class FeatureGenerator(BackgroundTaskThread):
    def __init__(self, bv, providers):
        super(FeatureGenerator, self).__init__("", False)
        self.bv = bv
        self.providers = providers

    def run(self):
        results={}
        func_len = len(self.bv.functions)
        for n, func in enumerate(self.bv.functions):
            self.progress = "Generating features (%d/%d)" % (n, func_len)
            idx=long(func.start)
            results[idx] = [None] * len(self.providers)
            for i,p in enumerate(self.providers):
                if isinstance(p, tuple):
                    p = p[0]
                results[idx][i] = p.calculate(func)
        self.progress = "Done generating features"    
        log_info(repr(results))
        if show_message_box("SimilarNinja","Do you want to save the results to the Binary Ninja database?", MessageBoxButtonSet.YesNoButtonSet, MessageBoxIcon.QuestionIcon) == 1:
            # Storing as JSON is wasteful, but more secure than Pickle... good enough for now
            self.bv.store_metadata("similarninja",json.dumps(results))
        else:
            out = open(get_save_filename_input("Filename to save function hashes:","*","output.json"),"wb")
            out.write(json.dumps(results))
            out.close()
        self.finish()

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
    def __init__(self, providers):
        super(SimilarNinjaComparer, self).__init__("", False)
        self.providers = providers


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
        data0_len = len(data0)
        data1_len = len(data1)

        log_info("Data sizes: %d %d" % (len(data0), len(data1)))
        matches=self.match_fvs(data0, data1)
        log_info("Data sizes after matching: %d %d" % (len(data0), len(data1)))
        
        # Inexact matches
        for func0 in list(data0.keys()): # So we can delete elements
            if func0 not in data0: continue
            feat0 = data0[func0]

            sims0 = [None] * len(self.providers)
            sim_avg0 = 0.0
            func_match = None
            feat_match = None
            for func1 in list(data1.keys()):
                if func1 not in data1: continue
                feat1 = data1[func1]

                sims = [None] * len(self.providers)
                weight_sum = 0.0
                for i, p in enumerate(self.providers):
                    weight = 1.0
                    if isinstance(p, tuple):
                        weight = p[1]
                        p = p[0]
                    sims[i] = p.compare(feat0[i],feat1[i])*weight
                    weight_sum += weight
                sim_avg = 0.0
                for s in sims:
                    sim_avg += s
                sim_avg = sim_avg / weight_sum        

                if sim_avg > sim_avg0:
                    sim_avg0 = sim_avg
                    sims0 = sims
                    func_match = func1
                    feat_match = feat1
                if sim_avg0 == 1.0: break # Exit early for perfect matches
            
            if func_match is not None:
                log_info("%x <-> %x %s (%f)\n%s %s" % (long(func0), long(func_match), repr(sims0), sim_avg0, feat0, feat_match))
                matches.append(((long(func0), feat0), (long(func_match), feat_match), sim_avg0))
                self.progress = "Matches: %d (%d <-> %d)" % (len(matches), data0_len, data1_len)
                del data0[func0]
                del data1[func_match]
        
        result_fn = get_save_filename_input("Filename to save comparison results:","*","compare.json")
        if result_fn is not None:
            out = open(result_fn, "wb")
            out.write(json.dumps(matches))
            out.close()
        self.finish()
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
    sn_comparer=SimilarNinjaComparer(PROVIDERS)
    sn_comparer.start()

def gen_feature(bv):
    fgen=FeatureGenerator(bv, PROVIDERS)
    fgen.start()

PluginCommand.register("SimilarNinja - Generate Feature Vectors", "Generates Feature Vectors for all functions", gen_feature)
PluginCommand.register("SimilarNinja - Compare", "Compare functions based on generated data files", compare)
