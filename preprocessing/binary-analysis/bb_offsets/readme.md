# bb_offsets

The scripts in this directory is used for collecting the basic block offsets information for the binaries inside the target SDK.
This type of information is useful when calculating EFF score during the combination.
It is based on IDAPython.

# File Usage Summary

- `idapython_bb_info.py`, the main logic for dumping basic block offsets information
- `merge_json.py`, merging several json files into one (one attack surface can contain several binaries)
- `gen.sh`, a script wrapping the usage of `merge_json.py` for the given five attack surfaces
- `*.json`, the binary information we collected for the five attack surfaces
