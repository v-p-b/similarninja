import sys
import json

in0 = {}
in1 = {}

def invert_map(m):
    out={}
    for k, v in m.iteritems():
        if v in out:
            out[long(v)] = -1 # We don't care about common SPP's
        else:
            out[long(v)] = int(k)
    return out

with open(sys.argv[1],"r") as f0:
    in0 = invert_map(json.loads(f0.read()))

with open(sys.argv[2],"r") as f1:
    in1 = invert_map(json.loads(f1.read()))

print(in1)

matches = 0
for spp, func in in0.iteritems():
    if func == -1:
        continue
    if spp in in1:
        print("%X <-> %X (%X)" % (in0[spp], in1[spp], spp))
        matches += 1

sys.stderr.write("Found %d matches." % (matches))