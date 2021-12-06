# APICraft

This prototype is presented in USENIX 2021 as "APICraft: Fuzz Driver Generation for Closed-source SDK Libraries".
It is mostly developed under MacOS 10.15.
Running it under other platforms is possible but currently we have no plan for further maintenance or migration.
For more introductory information about APICraft, please see its [website](https://sites.google.com/view/0xlib-harness) and [paper](https://www.usenix.org/conference/usenixsecurity21/presentation/zhang-cen).

Till now, we've released most of the source code of APICraft.
The binary analysis related code still need some time for cleaning up the code and passing copyright related review processes.

Some resources which potentially incurs copyright issues have been removed from this repository.
Complementarily, we documented the way to retrieve these resources.

# Usage

As stated in the paper, the general workflow of APICraft should be:

- Preprocessing (analyze the target sdk binary, the target sdk header files, and trace the consumer programs)
- Collect the dependencies (data and control dependencies) and combine the dependencies

You can follow the readme file inside the subdirectories for the detail of each step.
We're making an example based on one of the evaluated attack surface to guide interesting users to reproduce the whole workflow of APICraft.

# Cite

```
@inproceedings{0xlibfuzz:apicraft
  author    = {Cen Zhang and
               Xingwei Lin and
               Yuekang Li and
               Yinxing Xue and
               Jundong Xie and
               Hongxu Chen and
               Xinlei Ying and
               Jiashui Wang and
               Yang Liu},
  editor    = {Michael Bailey and
               Rachel Greenstadt},
  title     = {APICraft: Fuzz Driver Generation for Closed-source {SDK} Libraries},
  booktitle = {30th {USENIX} Security Symposium, {USENIX} Security 2021, August 11-13,
               2021},
  pages     = {2811--2828},
  publisher = {{USENIX} Association},
  year      = {2021},
  url       = {https://www.usenix.org/conference/usenixsecurity21/presentation/zhang-cen},
  timestamp = {Thu, 16 Sep 2021 17:32:10 +0200},
  biburl    = {https://dblp.org/rec/conf/uss/ZhangLLXXCYW021.bib},
  bibsource = {dblp computer science bibliography, https://dblp.org}
}
```
