# Deprecation

This project is deprecated as [binexport](https://github.com/google/binexport) supports Binary Ninja too these days.

# SimilarNinja Plugin (v0.2 alpha)
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
  * String histogram
* Others:
  * Basic Block Count
  * LLIL instruction types (LLIL_FEATURE_REDIRECT, LLIL_FEATURE_LOGIC, LLIL_FEATURE_ARITHMETIC)

Experimental infrastructure is available for exact and partial matching.

Early stage of development, code is unstable. 

Bugs? Very likely, please use the Issue Tracker!

### Why?

The licensing model of IDA sucks, we need tools for independent frameworks. Other design goals:

* Easy feature vector composition - creation of custom similarity metrics should be easy (at src level)
* No external databases - Redundant data storage should be avoided
  * SQLite based compatibility layer for Diaphora would be nice 

### Usage

The plugin adds two menu items: one for generating feature vetors for the functions of a binary, another for comparing the results of the previous one. Results can be saved to standalone JSON files or along with the analysis data in the BNDB database (the later is recommended). When comparing results the plugin tries to load raw JSON formatted data unless the extension of the opened file is ".bndb" - in that case the JSON object is read from database metadata. Comparison results can be saved to standalone JSON files.

Beware that some feature extractor classes can be stateful. When working with multiple views it is usually a good idea to `reload(similarninja)` in the Python Console when using it on a different tab.

## Customization

You can compose your custom feature vector generator by editing the `PROVIDERS` list. Each list element should be a `FeatureProvider` subclass instance or a tuple. The `FeatureProvider`  will be used to calculate similarity metrics for the corresponding vector position. In case of tuples the first element should be the `FeatureProvider` instance, while the second one is a float that will be used as a weight for the element. The default weight for each element is 1.0.    

### Examples

Using String Histogram with a Small Primes Product of the Stringly Connected Features and Function Flags. Both features have a weight of 1.0 when comparing:

```
[StringHistogramProvider(), 
SPPFeatureProvider([FuncStronglyConnectedFeatures, FuncFlagsFeatures])]
```


Using String Histogram with the Stringly Connected Features and Function Flags as separate prime products. String Histogram has doubled weight:

```
[(StringHistogramProvider(), 2.0), 
SPPFeatureProvider([FuncStronglyConnectedFeatures]), 
SPPFeatureProvider([FuncFlagsFeatures])]
```


## Testing

With the corresponding views open, save the current BinaryView objects in the Binary Ninja console:

```
>>> bv0=bv
# Switch views on the GUI
>>> bv1=bv
```

Invoke the tester function:

```
>>> similarninja.tester(bv0, bv1)
```

This will do the feature extraction (features stored in the database for later use) and comparison, then uses the available symbol information to measure accuracy. 

The function allows testing multiple feature provider compositions at once, refer to the source for details!

### Results

The following results are based on debug information contained in unstripped binaries (exact function name match).

The current algorithm for partial matches is very liberal and will try to find a match for everything - this is the reason of high incorrect match numbers. However these "incorrect" numbers also contain actual good matches (like matches between `shaX_process_blockN()` functions). 

### Busybox 

#### 1.29.1 vs. 1.29.2 x64 ELF

| Func # | Correct match | Incorrect match |
|--------|---------------|-----------------|
| 3114   | 1600 (51.3%)  | 1488 (47.8%)    |

Feature vector providers:
```
[SPPFeatureProvider([BBLTypeFeatures]), SPPFeatureProvider([BBLEdgeFeatures]), SPPFeatureProvider([FuncInstructionFeatures]), SPPFeatureProvider([FuncStronglyConnectedFeatures, FuncFlagsFeatures]), DigraphFeatureProvider(),BBLCountProvider()]
```

| Func # | Correct match | Incorrect match |
|--------|---------------|-----------------|
| 3114   | 2098 (67.4%)  | 981 (31.5%)     |

Feature vector providers:
```
[SPPFeatureProvider([BBLTypeFeatures]), SPPFeatureProvider([BBLEdgeFeatures]), SPPFeatureProvider([FuncInstructionFeatures]), SPPFeatureProvider([FuncStronglyConnectedFeatures, FuncFlagsFeatures]), DigraphFeatureProvider(), StringHistogramProvider()] 
```


### SQLite

#### 3.25.03 vs. 3.25.00 x64 ELF*

| Func # | Correct match | Incorrect match |
|--------|---------------|-----------------|
| 3122   | 1432 (45.9%)  | 1689 (54.1%)    |

Feature vector providers:
```
[SPPFeatureProvider([BBLTypeFeatures]), SPPFeatureProvider([BBLEdgeFeatures]), SPPFeatureProvider([FuncInstructionFeatures]), SPPFeatureProvider([FuncStronglyConnectedFeatures, FuncFlagsFeatures]), DigraphFeatureProvider(),BBLCountProvider()]
```

| Func # | Correct match | Incorrect match |
|--------|---------------|-----------------|
| 3122   | 1618 (51.8%)  | 1503 (48.1%)    |

Feature vector providers:
```
[SPPFeatureProvider([BBLTypeFeatures]), SPPFeatureProvider([BBLEdgeFeatures]), SPPFeatureProvider([FuncInstructionFeatures]), SPPFeatureProvider([FuncStronglyConnectedFeatures, FuncFlagsFeatures]), DigraphFeatureProvider(), StringHistogramProvider()] 
```

## TODO

A lot of things...

* More matcher algorithms
  * Algorithms from the [original paper](https://census-labs.com/media/efficient-features-bindiff.pdf):
    * Markov lumping
    * Instruction histogram (with capstone/pyxed/other external lib?)
* Better integration with the UI
* Without a BinaryView we loose cross-function control-flow data, so function predecessors/successors can't be discovered during matching
  * Multiple ways to handle this, have to decide which way to go...
* LICENSE file...

### Binary Ninja API wishlist

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

