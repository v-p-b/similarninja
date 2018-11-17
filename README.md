# SimilarNinja Plugin (v0.1 alpha)
Author: **buherator**
_Find similar functions with Binary Ninja_
## Description:

This is a partial implementation of the [KOKA algorithm](http://joxeankoret.com/blog/2018/11/04/new-cfg-based-heuristic-diaphora/) for CFG matching. 

Early stage of development, code is unstable. 

### Why?

The licensing model of IDA sucks, we need tools for independent frameworks. Also see Goals.

### Goals

* Easy fine tuning at src level
* No external databases
  * SQLite based compatibility layer for Diaphora would be nice though

## TODO

A lot of things...

* More mathcer algorithms
  * Support for non-SSP based results
  * Algorithms from the [original paper](https://census-labs.com/media/efficient-features-bindiff.pdf):
    * Dominance tree based 
* Calculate similarity levels
* Better integration with the UI

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
