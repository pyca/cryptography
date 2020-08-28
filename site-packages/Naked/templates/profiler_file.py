#!/usr/bin/env python
# encoding: utf-8

# VARS = --none--
profiler_file_string = """
#!/usr/bin/env python
# encoding: utf-8

import cProfile, pstats, StringIO

def profile():
    #------------------------------------------------------------------------------
    # Setup a profile
    #------------------------------------------------------------------------------
    pr = cProfile.Profile()
    #------------------------------------------------------------------------------
    # Enter setup code below
    #------------------------------------------------------------------------------
        # Optional: include setup code here


    #------------------------------------------------------------------------------
    # Start profiler
    #------------------------------------------------------------------------------
    pr.enable()

    #------------------------------------------------------------------------------
    # BEGIN profiled code block
    #------------------------------------------------------------------------------
        # include profiled code here


    #------------------------------------------------------------------------------
    # END profiled code block
    #------------------------------------------------------------------------------
    pr.disable()
    s = StringIO.StringIO()
    sortby = 'cumulative'
    ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
    ps.strip_dirs().sort_stats("time").print_stats()
    print(s.getvalue())

if __name__ == '__main__':
    profile()
"""
