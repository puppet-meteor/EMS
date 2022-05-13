"""Integration code for ems_lto fuzzer."""

import os
import json
import shutil
import subprocess
from fuzzers.afl import fuzzer as afl_fuzzer
from fuzzers import utils





def build():
    """Build ems_lto."""

    os.environ['CC'] = '/out/afl/lto_mode/afl-clang-lto'
    os.environ['CXX'] = '/out/afl/lto_mode/afl-clang-lto++'
    build_directory = os.environ['OUT']
    edge_file = '/out/ems_lto_edges.txt'
    os.environ['AFL_LLVM_DOCUMENT_IDS'] = edge_file
    os.environ['AFL_INST_RATIO'] = '35'


    if os.path.isfile('/usr/local/bin/llvm-ranlib-13'):
        os.environ['RANLIB'] = 'llvm-ranlib-13'
        os.environ['AR'] = 'llvm-ar-13'
        os.environ['AS'] = 'llvm-as-13'
    elif os.path.isfile('/usr/local/bin/llvm-ranlib-12'):
        os.environ['RANLIB'] = 'llvm-ranlib-12'
        os.environ['AR'] = 'llvm-ar-12'
        os.environ['AS'] = 'llvm-as-12'
    else:
        os.environ['RANLIB'] = 'llvm-ranlib'
        os.environ['AR'] = 'llvm-ar'
        os.environ['AS'] = 'llvm-as'


    os.environ['FUZZER_LIB'] = '/libAFL.a'

    build_flags = os.environ['CFLAGS']
    if build_flags.find('array-bounds') != -1:
        os.environ['CC'] = '/out/afl/afl-clang-fast'
        os.environ['CXX'] = '/out/afl/afl-clang-fast++'
        cmd1 = 'unset AFL_LLVM_DOCUMENT_IDS'
        os.system(cmd1)

    new_env = os.environ.copy()
    utils.build_benchmark(env=new_env)
    print('[post_build] Copying afl-fuzz to $OUT directory')
    # Copy out the afl-fuzz binary as a build artifact.
    shutil.copy('/out/afl/lto_mode/afl-clang-lto', os.environ['OUT'])
    shutil.copy('/out/afl/afl-fuzz', os.environ['OUT'])
    shutil.copy('/out/afl/static.sh', os.environ['OUT'])
    shutil.copy('/out/afl/ems4.txt', os.environ['OUT'])




def create_seed_file_for_empty_corpus(input_corpus):
    """Create a fake seed file in an empty corpus, skip otherwise."""
    if os.listdir(input_corpus):
        # Input corpus has some files, no need of a seed file. Bail out.
        return

    print('Creating a fake seed file in empty corpus directory.')
    default_seed_file = os.path.join(input_corpus, 'default_seed')
    with open(default_seed_file, 'w') as file_handle:
        file_handle.write('hi')




def check_skip_det_compatible(additional_flags):
    """ Checks if additional flags are compatible with '-d' option"""
    # AFL refuses to take in '-d' with '-M' or '-S' options for parallel mode.
    # (cf. https://github.com/google/AFL/blob/8da80951/afl-fuzz.c#L7477)
    if '-M' in additional_flags or '-S' in additional_flags:
        return False
    return True





def run_afl_fuzz(input_corpus,
                 output_corpus,
                 target_binary,
                 additional_flags=None,
                 hide_output=False):
    """Run afl-fuzz."""
    # Spawn the afl fuzzing process.
    print('[run_afl_fuzz] Now path: ' + os.getcwd())
    print('[run_afl_fuzz] Running target with afl-fuzz')
    command = [
        '/out/afl-fuzz',
        '-i',
        input_corpus,
        '-o',
        output_corpus,
        # Use no memory limit as ASAN doesn't play nicely with one.
        '-m',
        'none',
        '-t',
        '1000+',  # Use same default 1 sec timeout, but add '+' to skip hangs.
    ]
    # Use '-d' to skip deterministic mode, as long as it it compatible with
    # additional flags.
    if not additional_flags or check_skip_det_compatible(additional_flags):
        command.append('-d')
    if additional_flags:
        command.extend(additional_flags)
    dictionary_path = utils.get_dictionary_path(target_binary)
    if dictionary_path:
        command.extend(['-x', dictionary_path])
    command += [
        '--',
        target_binary,
        # Pass INT_MAX to afl the maximize the number of persistent loops it
        # performs.
        '2147483647'
    ]
    print('[run_afl_fuzz] Running command: ' + ' '.join(command))
    output_stream = subprocess.DEVNULL if hide_output else None
    subprocess.check_call(command, stdout=output_stream, stderr=output_stream)





def fuzz(input_corpus, output_corpus, target_binary):
    """Run ems_lto."""

    create_seed_file_for_empty_corpus(input_corpus)

    cmd1 = 'bash /out/static.sh   '  +  target_binary + '  /out/dicttest'
    print(cmd1 )
    os.system(cmd1)


    # Tell AFL to not use its terminal UI so we get usable logs.
    os.environ['AFL_NO_UI'] = '1'
    # Skip AFL's CPU frequency check (fails on Docker).
    os.environ['AFL_SKIP_CPUFREQ'] = '1'
    # No need to bind affinity to one core, Docker enforces 1 core usage.
    os.environ['AFL_NO_AFFINITY'] = '1'
    # AFL will abort on startup if the core pattern sends notifications to
    # external programs. We don't care about this.
    os.environ['AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES'] = '1'
    # Don't exit when crashes are found. This can happen when corpus from
    # OSS-Fuzz is used.
    os.environ['AFL_SKIP_CRASHES'] = '1'
    # Shuffle the queue
    os.environ['AFL_SHUFFLE_QUEUE'] = '1'

    if os.path.isfile('/out/ems_lto_edges.txt'):
        edge_file = '/out/ems_lto_edges.txt'
        os.environ['AFL_LLVM_DOCUMENT_IDS'] = edge_file


    run_afl_fuzz(
        input_corpus,
        output_corpus,
        target_binary,
        additional_flags=[
            # Enable Mopt mutator with pacemaker fuzzing mode at first. This
            # is also recommended in a short-time scale evaluation.
            '-L',
            '0',
            '-G',
            '/out/ems4.txt',
            '-x',
            '/out/dicttest',
        ])

