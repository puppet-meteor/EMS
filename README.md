# EMS
### 1. Description
Hi guys, we open source the prototype of EMS. EMS is a coverage-based fuzzer that utilizes a customized  Probabilistic Byte Orientation Model (PBOM) to reuse the efficient mutation strategies from inter- and intra-trials. As shown in Table 8 of the [paper](https://www.ndss-symposium.org/wp-content/uploads/2022-162-paper.pdf), more than half of the efficient mutation strategies can be collected in 5 hours. So EMS mainly improves the fuzzing performance by utilizing efficient strategies more times. 


### 2. Introduction to Usage

To collect efficient mutation strategies as inter-PBOM, you can run the following cmds. 
```
# export EMS_INTER_TRIAL_PBOM=/path_to_store/random_file_name.txt
# /ems/afl-fuzz -i $input -o $output (-L 0 -t 600+ -m 5000) (-V $time if you would like to control fuzzing duration) -- /path/to/program [...params...] 
```
After the fuzzing process is done, you can obtain the random_file_name.txt as inter-PBOM for other fuzzing trials. 

In our source code, we provide an initial inter-PBOM named ems4.txt, which is collected from a 5-hour trial on `pdfimages`.
Then, to utilize this inter-PBOM, you can run a cmd as follows. 
```# /ems/afl-fuzz -i $input -o $output  -G /ems/ems4.txt  (-L 0 -t 600+ -m 5000) (-V $time if you would like to control fuzzing duration) -- /path/to/program [...params...] ```


We also implement instrumentation similar to the one in [CollAFL](http://netsec.ccert.edu.cn/files/papers/sp18-collafl.pdf). To utilize this instrumentation, you need to install llvm 11+. Then, compile the instrumentation in `/ems/lto_mode`, in which you can obtain `afl-clang-lto` and `afl-clang-lto++`. The cmds to utilize this instrumentation are as follows. 
```
# export AFL_LLVM_DOCUMENT_IDS=/path_to_store/ems_lto_edges.txt
# export CC=/ems/lto_mode/afl-clang-lto
# export CXX=/ems/lto_mode/afl-clang-lto++
# [...compile target programs...] 
```
Then, you achieve to instrument target programs without collision issues and obtain `ems_lto_edges.txt`, which stores the size of bitmap. Note that if you use this instrumentation, you have to load the bitmap size as follows.
```
# export AFL_LLVM_DOCUMENT_IDS=/path_to_store/ems_lto_edges.txt

# /ems/afl-fuzz -i $input -o $output  -G /ems/ems4.txt  (-L 0 -t 600+ -m 5000) (-V $time if you would like to control fuzzing duration) -- /path/to/program [...params...] 
```

We also provide a dockerfile for FuzzBench testing. You can simply copy `ems_fuzzbench` to `/fuzzbench/fuzzers/` and run `make format`. Then, you can evaluate EMS on FuzzBench. It's a little awkward that our `lto_mode` instrumentation cannot work on all the target programs of FuzzBench. Users can refer to the instrumentation of [AFL++](https://github.com/AFLplusplus/AFLplusplus) for more insights. AFL++ is a powerful fuzzer with extremely high update frequency, which contains multiple kinds of instrumentations and new designs like improving the implementation of forkserver. 


Having fun with EMS. See you next time!


### Citation:
```
Coming soon. 
```

