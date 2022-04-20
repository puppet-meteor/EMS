# EMS
### 1. Description
Hi guys, we open source the prototype of EMS. EMS is a coverage-based fuzzer that utilizes a customized  Probabilistic Byte Orientation Model (PBOM) to reuse the efficient mutation strategies from inter- and intra-trials. As shown in Table 8 of the [paper](https://www.ndss-symposium.org/wp-content/uploads/2022-162-paper.pdf), more than half of the efficient mutation strategies can be collected in 5 hours. So EMS mainly improves the fuzzing performance by utilizing efficient strategies more times. 


### 2. Parameter Introduction

To collect efficient mutation strategies as inter-PBOM, you can run the following cmds. 
`
# export EMS_INTER_TRIAL_PBOM=/path_to_store/random_file_name.txt
# /ems/afl-fuzz -i $input -o $output (-L 0 -t 600+  -m 5000) (-V $time if you would like to control fuzzing duration) -- /path/to/program [...params...] 
`
After the fuzzing process is done, you can obtain the random_file_name.txt as inter-PBOM for other fuzzing trials. 

In our source code, we provide a initial inter-PBOM named ems4.txt, which is collected from a 5-hour trial on `pdfimages`.
Then, to utilize this inter-PBOM, you can run a cmd as follows. 
`
# /ems/afl-fuzz -i $input -o $output  -G /ems/ems4.txt  (-L 0 -t 600+  -m 5000) (-V $time if you would like to control fuzzing duration) -- /path/to/program [...params...] 
`





<br>`-L` controls the time to move on to the pacemaker fuzzing mode.
<br>`-L t:` when MOpt-AFL finishes the mutation of one input, if it has not discovered any new unique crash or path for more than t min, MOpt-AFL will enter the pacemaker fuzzing mode. 

<br>Setting 0 will enter the pacemaker fuzzing mode at first, which is recommended in a short time-scale evaluation (like 2 hours). 
<del><br>For instance, it may take three or four days for MOpt-AFL to enter the pacemaker fuzzing mode when `-L 30`. </del>

Hey guys, I realize that most experiments may last no longer than 24 hours. You may have trouble selecting a suitable value of 'L' without testing. So I modify the code in order to employ '-L 1' as the default setting. This means you do not have to add the parameter 'L' to launch the MOpt scheme. If you wish, provide a parameter '-L t' in the cmd can adjust the time when MOpt will enter the pacemaker fuzzing mode as aforementioned. Whether MOpt enters the pacemaker fuzzing mode has a great influence on the fuzzing performance in some cases as shown in our paper. 
<br>'-L 1' may not be the best choice  but will be acceptable in most cases. I may provide several experiment results to show this situation. 


 



Other important parameters can be found in afl-fuzz.c, for instance, 
<br>`swarm_num:` the number of the PSO swarms used in the fuzzing process.
<br>`period_pilot:` how many times MOpt-AFL will execute the target program in the pilot fuzzing module, then it will enter the core fuzzing module. 
<br>`period_core:` how many times MOpt-AFL will execute the target program in the core fuzzing module, then it will enter the PSO updating module. 
<br>`limit_time_bound:` control how many interesting test cases need to be found before MOpt-AFL quits the pacemaker fuzzing mode and reuses the deterministic stage. 
0 < `limit_time_bound` < 1, MOpt-AFL-tmp.  `limit_time_bound` >= 1, MOpt-AFL-ever. 

Having fun with EMS. 


### Citation:
```
Coming soon. 
```

