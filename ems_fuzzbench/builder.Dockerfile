ARG parent_image
FROM $parent_image                         



RUN apt-get update && \
    apt-get install -y wget libstdc++-5-dev libtool-bin automake flex bison \
                       libglib2.0-dev libpixman-1-dev python3-setuptools unzip \
                       apt-utils apt-transport-https ca-certificates  



RUN git clone https://github.com/puppet-part2/test.git /out/afl && cd /out/afl && git checkout  a75f17b5ec1c2cfdd2592a1df3a2aefe28bdced0



RUN  chmod -R 777 /out/afl  
RUN cd /out/afl && unset CFLAGS && unset CXXFLAGS && export AFL_NO_X86=1 && make clean && make    && cd /out/afl/lto_mode && make  && cd /out/afl/llvm_mode && make


RUN apt-get update && \
     apt-get install wget -y &&  \
     wget https://raw.githubusercontent.com/llvm/llvm-project/5feb80e748924606531ba28c97fe65145c65372e/compiler-rt/lib/fuzzer/afl/afl_driver.cpp -O /out/afl/afl_driver.cpp && \
     clang++ -stdlib=libc++ -std=c++11 -O2 -c /out/afl/afl_driver.cpp && \
     ar r /libAFL.a *.o







