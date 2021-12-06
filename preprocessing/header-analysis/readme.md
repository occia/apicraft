# Header analysis

Header analysis tool outputs necessary inputs for data dependency analysis.
Specifically, the outputs are:

- meta information (the type information of parameters of each API function) used for data dependency collection
- tracer code used for tracing consumer program

It is based on libclang python binding.

# Usage

## Prerequisite

### Retrieving patched libclang 

We patched libclang python bindings for better analysis of objc language.
However, to avoid the potential copyright issues, we made it into a seperate [repo](https://github.com/occia/libclang-python-bindings).
Therefore, you need to download it using the following command before running the preprocessing code.

```bash
git clone https://github.com/occia/libclang-python-bindings
mv libclang-python-bindings/clang .
```

### Retrieving MacOS SDK

You need to get MacOS SDK from either xcode or [some public released repositories](https://github.com/phracker/MacOSX-SDKs) for analyzing your target.
Specifically, APICraft used [this](https://drive.google.com/file/d/1QfwQKpwV9jZ0c7JKh1oW8GHDIgLMN6o8/view?usp=sharing).

## Run

To generate the required information for the five attack surfaces, use the following command:

```bash
# run any of the following bash script for each attack surface
bash audio.sh/cgpdf.sh/font.sh/image.sh/rtf.sh
```

Specifically, the above script calls `extract.py` whose command line option meaning is listed as follows:

```bash
Usage:

python extract.py \
        output_meta_info.json \
        output_generated_tracer_tool.mm \
        blacklist_cfg_file \
        header_file1 \
        header_file2 \
        header_file3 \
        header_file4 \
        header_file5 \
        header_file6 \
        ...
```

# json output format of the meta information

`tkey`, `fkey` without quotes are variables.

TODO: Some fields are not recorded here.

```
{
  'fmap': {
    fkey: {
      'in': [ 
        {'tag': 'arg%d' or 'ret', 'tkey': tkey, 'cmp_type': cmp_type, 'need_cmp': bool, 'is_pointer': bool},
        ...
      ],
      'out': [
        {'tag': 'arg%d' or 'ret', 'tkey': tkey, 'cmp_type': cmp_type, 'need_cmp': bool, 'is_pointer': bool},
        ...
      ],
      'tspell': string,
      'ctspell': string,
      'arg_sizes': [ int, ... ], /* last one is the ret size */
      'mangled_name' : string,
    },
    ...
  },
  'tmap': {
    tkey: {
      'size': int (in bits),
      'pointees': [
        {'offset': int, 'tkey': tkey},
        ...
      ],
      'tspell': string,
      'ctspell': string,
    },
    ...
  }
}
```

