# SimilarNinja Plugin (v0.1 alpha)
Author: **buherator**
_Find similar functions with Binary Ninja_
## Description:

This is a partial implementation of the [KOKA algorithm](http://joxeankoret.com/blog/2018/11/04/new-cfg-based-heuristic-diaphora/) for CFG matching. 

Currently the following algorithms are implemented:

* KOKA features bound together in an SPP hash:
  * NODE_ENTRY, NODE_EXIT, NODE_NORMAL
  * EDGE_OUT_CONDITIONAL, EDGE_IN_CONDITIONAL
  * FEATURE_FUNC_NO_RET, FEATURE_FUNC_LIB
* Features from the [original paper](https://census-labs.com/media/efficient-features-bindiff.pdf):
  * Digraph Signature
* Others:
  * Basic Block Count

Experimental infrastructure is available for exact and partial matching.

Early stage of development, code is unstable. 

### Why?

The licensing model of IDA sucks, we need tools for independent frameworks. Also see Goals.

### Goals

* Easy feature vector composition (at src level)
* No external databases
  * SQLite based compatibility layer for Diaphora would be nice though

## Testing

Export and compare features of two binaries with symbols. With the corresponding views open, save the current BinaryView objects in the Binary Ninja console:

```
>>> bv0=bv
# Switch views on the GUI
>>> bv1=bv
```

Invoke the tester function:

```
>>> similarninja.tester(bv0, bv1, "/path/to/comparison.json")
```

### Results

### Busybox 

*1.29.1 vs. 1.29.2 x64 ELF*

| Func # | Correct match | Incorrect match |
|--------|---------------|-----------------|
| 3114   | 1600 (51.3%)  | 1488 (47.8%)    |

Feature vector providers:
```
[SPPFeatureProvider([BBLTypeFeatures]), SPPFeatureProvider([BBLEdgeFeatures]), SPPFeatureProvider([FuncInstructionFeatures]), SPPFeatureProvider([FuncStronglyConnectedFeatures, FuncFlagsFeatures]), DigraphFeatureProvider(),BBLCountProvider()]
```

### SQLite

*3.25.03 vs. 3.25.00 x64 ELF*

| Func # | Correct match | Incorrect match |
|--------|---------------|-----------------|
| 3122   | 1432 (45.9%)  | 1689 (54.1%)    |

Feature vector providers:
```
[SPPFeatureProvider([BBLTypeFeatures]), SPPFeatureProvider([BBLEdgeFeatures]), SPPFeatureProvider([FuncInstructionFeatures]), SPPFeatureProvider([FuncStronglyConnectedFeatures, FuncFlagsFeatures]), DigraphFeatureProvider(),BBLCountProvider()]
```

## TODO

A lot of things...

* More matcher algorithms
  * Algorithms from the [original paper](https://census-labs.com/media/efficient-features-bindiff.pdf):
    * Markov lumping
    * String histogram
    * Instruction histogram (with capstone/pyxed/other external lib?)
* Better integration with the UI
* Without a BinaryView we loose cross-function control-flow data, so function predecessors/successors can't be discovered during matching
  * Multiple ways to handle this, have to decide which way to go...

### Binary Ninja API deficiencies

* Instruction level classification  
* Data XRefs


## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * release - 0
 * dev - 1.0.dev-576

## Required Dependencies

The following dependencies are required for this plugin:

 * pip - 
 * installers - 
 * other - 
 * apt - 

## License
This plugin is released under a GPLv2 license as required by Diaphora. 

Adding a proper LICENSE file is TODO...
