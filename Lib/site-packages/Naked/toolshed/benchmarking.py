#!/usr/bin/env python
# encoding: utf-8

import sys
import time
import gc
from functools import wraps

#------------------------------------------------------------------------------
# [ timer function decorator ]
#  runs timed repetitions of the decorated function in a single trial
#  default is 100,000 repetitions in the trial
#  reports the results of the trial
#  Usage example:
#       from Naked.toolshed.benchmarking import timer
#       @timer
#       def myfunction():
#------------------------------------------------------------------------------
def timer(func, repetitions=100000):
    @wraps(func)
    def wrapper(*args, **kwargs):
        sys.stdout.write("Starting " + str(repetitions) + " repetitions of " + func.__name__ + "()...")
        sys.stdout.flush()
        print(" ")
        # disable garbage collection
        gc.collect()
        gc.disable()
        start = time.time()
        for x in range(repetitions):
            result = func(*args, **kwargs)
        end = time.time()
        gc.enable()  # re-enable garbage collection
        gc.collect()
        print(str(repetitions) + " repetitions of " + func.__name__ + " : " + str(end-start) + " sec")
        return result
    return wrapper

#------------------------------------------------------------------------------
# [ timer_X function decorators ]
#   replicate the above decorator with different number of repetitions
#------------------------------------------------------------------------------

def timer_10(func, repetitions=10):
    @wraps(func)
    def wrapper(*args, **kwargs):
        sys.stdout.write("Starting " + str(repetitions) + " repetitions of " + func.__name__ + "()...")
        sys.stdout.flush()
        print(" ")
        # disable garbage collection
        gc.collect()
        gc.disable()
        start = time.time()
        for x in range(repetitions):
            result = func(*args, **kwargs)
        end = time.time()
        gc.enable()  # re-enable garbage collection
        gc.collect()
        print(str(repetitions) + " repetitions of " + func.__name__ + " : " + str(end-start) + " sec")
        return result
    return wrapper

def timer_100(func, repetitions=100):
    @wraps(func)
    def wrapper(*args, **kwargs):
        sys.stdout.write("Starting " + str(repetitions) + " repetitions of " + func.__name__ + "()...")
        sys.stdout.flush()
        print(" ")
        # disable garbage collection
        gc.collect()
        gc.disable()
        start = time.time()
        for x in range(repetitions):
            result = func(*args, **kwargs)
        end = time.time()
        gc.enable()  # re-enable garbage collection
        gc.collect()
        print(str(repetitions) + " repetitions of " + func.__name__ + " : " + str(end-start) + " sec")
        return result
    return wrapper

def timer_1k(func, repetitions=1000):
    @wraps(func)
    def wrapper(*args, **kwargs):
        sys.stdout.write("Starting " + str(repetitions) + " repetitions of " + func.__name__ + "()...")
        sys.stdout.flush()
        print(" ")
        # disable garbage collection
        gc.collect()
        gc.disable()
        start = time.time()
        for x in range(repetitions):
            result = func(*args, **kwargs)
        end = time.time()
        gc.enable()  # re-enable garbage collection
        gc.collect()
        print(str(repetitions) + " repetitions of " + func.__name__ + " : " + str(end-start) + " sec")
        return result
    return wrapper

def timer_10k(func, repetitions=10000):
    @wraps(func)
    def wrapper(*args, **kwargs):
        sys.stdout.write("Starting " + str(repetitions) + " repetitions of " + func.__name__ + "()...")
        sys.stdout.flush()
        print(" ")
        # disable garbage collection
        gc.collect()
        gc.disable()
        start = time.time()
        for x in range(repetitions):
            result = func(*args, **kwargs)
        end = time.time()
        gc.enable()  # re-enable garbage collection
        gc.collect()
        print(str(repetitions) + " repetitions of " + func.__name__ + " : " + str(end-start) + " sec")
        return result
    return wrapper

def timer_1m(func, repetitions=1000000):
    @wraps(func)
    def wrapper(*args, **kwargs):
        sys.stdout.write("Starting " + str(repetitions) + " repetitions of " + func.__name__ + "()...")
        sys.stdout.flush()
        print(" ")
        # disable garbage collection
        gc.collect()
        gc.disable()
        start = time.time()
        for x in range(repetitions):
            result = func(*args, **kwargs)
        end = time.time()
        gc.enable()  # re-enable garbage collection
        gc.collect()
        print(str(repetitions) + " repetitions of " + func.__name__ + " : " + str(end-start) + " sec")
        return result
    return wrapper

#------------------------------------------------------------------------------
# [ timer_trials_benchmark decorator function ]
#   time a function and compare to a benchmark function
#   default is 10 trials x 100,000 repetitions/trial for each function
#   Results:
#     - Mean of the 10 trials of the test function
#     - standard deviation of the 10 trials (if numpy is available)
#     - result for 100,000 repetitions of the benchmark function
#     - ratio of the test : benchmark function results
#     Usage example:
#       from Naked.toolshed.benchmarking import timer_trials_benchmark
#       @timer_trials_benchmark
#       def myfunction():
#------------------------------------------------------------------------------
def timer_trials_benchmark(func, repetitions=100000, trials=10):
    @wraps(func)
    def wrapper(*args, **kwargs):
        sys.stdout.write("Starting timed trials of " + func.__name__ + "()")
        sys.stdout.flush()
        result_list = []
        benchmark_list = []
        # disable garbage collection
        gc.collect()
        gc.disable()
        for x in range(trials):
            # test function
            start = time.time()
            for y in range(repetitions):
                func(*args, **kwargs)
            end = time.time()
            result = func(*args, **kwargs)
            result_list.append(end-start)
            # benchmark function
            L = []
            start2 = time.time()
            for j in range(repetitions):
                for i in range(10):
                    L.append(i)
            end2 = time.time()
            benchmark_list.append(end2 - start2)
            sys.stdout.write(".")
            sys.stdout.flush()
        gc.enable()  # re-enable garbage collection
        gc.collect()
        print(" ")
        n = 1
        for run in result_list:
            print("Trial " + str(n) + ":\t" + str(run))
            n += 1
        print("-"*50)
        mean = sum(result_list)/len(result_list)
        mean_benchmark = sum(benchmark_list)/len(benchmark_list)
        print("Mean for " + str(repetitions) + " repetitions: " + str(mean) + " sec")
        try:
            import numpy as np
            array = np.array(result_list)
            print( "Standard Deviation: " + str(np.std(array)))
        except ImportError as ie:
            pass
        print("Mean per repetition: " + str(mean/repetitions) + " sec")
        print("Mean for " + str(repetitions) + " of benchmark function:" + str(mean_benchmark) + " sec")
        print("Ratio: " + str(mean/mean_benchmark))
        return result
    return wrapper

#------------------------------------------------------------------------------
# [ timer_trials_benchmark_X decorators ]
#    additional benchmark decorators that replicate the above function with different # repetitions
#------------------------------------------------------------------------------
def timer_trials_benchmark_10(func, repetitions=10, trials=10):
    @wraps(func)
    def wrapper(*args, **kwargs):
        sys.stdout.write("Starting timed trials of " + func.__name__ + "()")
        sys.stdout.flush()
        result_list = []
        benchmark_list = []
        # disable garbage collection
        gc.collect()
        gc.disable()
        for x in range(trials):
            # test function
            start = time.time()
            for y in range(repetitions):
                func(*args, **kwargs)
            end = time.time()
            result = func(*args, **kwargs)
            result_list.append(end-start)
            # benchmark function
            L = []
            start2 = time.time()
            for j in range(repetitions):
                for i in range(10):
                    L.append(i)
            end2 = time.time()
            benchmark_list.append(end2 - start2)
            sys.stdout.write(".")
            sys.stdout.flush()
        gc.enable()  # re-enable garbage collection
        gc.collect()
        print(" ")
        n = 1
        for run in result_list:
            print("Trial " + str(n) + ":\t" + str(run))
            n += 1
        print("-"*50)
        mean = sum(result_list)/len(result_list)
        mean_benchmark = sum(benchmark_list)/len(benchmark_list)
        print("Mean for " + str(repetitions) + " repetitions: " + str(mean) + " sec")
        try:
            import numpy as np
            array = np.array(result_list)
            print( "Standard Deviation: " + str(np.std(array)))
        except ImportError as ie:
            pass
        print("Mean per repetition: " + str(mean/repetitions) + " sec")
        print("Mean for " + str(repetitions) + " of benchmark function:" + str(mean_benchmark) + " sec")
        print("Ratio: " + str(mean/mean_benchmark))
        return result
    return wrapper

def timer_trials_benchmark_100(func, repetitions=100, trials=10):
    @wraps(func)
    def wrapper(*args, **kwargs):
        sys.stdout.write("Starting timed trials of " + func.__name__ + "()")
        sys.stdout.flush()
        result_list = []
        benchmark_list = []
        # disable garbage collection
        gc.collect()
        gc.disable()
        for x in range(trials):
            # test function
            start = time.time()
            for y in range(repetitions):
                func(*args, **kwargs)
            end = time.time()
            result = func(*args, **kwargs)
            result_list.append(end-start)
            # benchmark function
            L = []
            start2 = time.time()
            for j in range(repetitions):
                for i in range(10):
                    L.append(i)
            end2 = time.time()
            benchmark_list.append(end2 - start2)
            sys.stdout.write(".")
            sys.stdout.flush()
        gc.enable()  # re-enable garbage collection
        gc.collect()
        print(" ")
        n = 1
        for run in result_list:
            print("Trial " + str(n) + ":\t" + str(run))
            n += 1
        print("-"*50)
        mean = sum(result_list)/len(result_list)
        mean_benchmark = sum(benchmark_list)/len(benchmark_list)
        print("Mean for " + str(repetitions) + " repetitions: " + str(mean) + " sec")
        try:
            import numpy as np
            array = np.array(result_list)
            print( "Standard Deviation: " + str(np.std(array)))
        except ImportError as ie:
            pass
        print("Mean per repetition: " + str(mean/repetitions) + " sec")
        print("Mean for " + str(repetitions) + " of benchmark function:" + str(mean_benchmark) + " sec")
        print("Ratio: " + str(mean/mean_benchmark))
        return result
    return wrapper

def timer_trials_benchmark_1k(func, repetitions=1000, trials=10):
    @wraps(func)
    def wrapper(*args, **kwargs):
        sys.stdout.write("Starting timed trials of " + func.__name__ + "()")
        sys.stdout.flush()
        result_list = []
        benchmark_list = []
        # disable garbage collection
        gc.collect()
        gc.disable()
        for x in range(trials):
            # test function
            start = time.time()
            for y in range(repetitions):
                func(*args, **kwargs)
            end = time.time()
            result = func(*args, **kwargs)
            result_list.append(end-start)
            # benchmark function
            L = []
            start2 = time.time()
            for j in range(repetitions):
                for i in range(10):
                    L.append(i)
            end2 = time.time()
            benchmark_list.append(end2 - start2)
            sys.stdout.write(".")
            sys.stdout.flush()
        gc.enable()  # re-enable garbage collection
        gc.collect()
        print(" ")
        n = 1
        for run in result_list:
            print("Trial " + str(n) + ":\t" + str(run))
            n += 1
        print("-"*50)
        mean = sum(result_list)/len(result_list)
        mean_benchmark = sum(benchmark_list)/len(benchmark_list)
        print("Mean for " + str(repetitions) + " repetitions: " + str(mean) + " sec")
        try:
            import numpy as np
            array = np.array(result_list)
            print( "Standard Deviation: " + str(np.std(array)))
        except ImportError as ie:
            pass
        print("Mean per repetition: " + str(mean/repetitions) + " sec")
        print("Mean for " + str(repetitions) + " of benchmark function:" + str(mean_benchmark) + " sec")
        print("Ratio: " + str(mean/mean_benchmark))
        return result
    return wrapper

def timer_trials_benchmark_10k(func, repetitions=10000, trials=10):
    @wraps(func)
    def wrapper(*args, **kwargs):
        sys.stdout.write("Starting timed trials of " + func.__name__ + "()")
        sys.stdout.flush()
        result_list = []
        benchmark_list = []
        # disable garbage collection
        gc.collect()
        gc.disable()
        for x in range(trials):
            # test function
            start = time.time()
            for y in range(repetitions):
                func(*args, **kwargs)
            end = time.time()
            result = func(*args, **kwargs)
            result_list.append(end-start)
            # benchmark function
            L = []
            start2 = time.time()
            for j in range(repetitions):
                for i in range(10):
                    L.append(i)
            end2 = time.time()
            benchmark_list.append(end2 - start2)
            sys.stdout.write(".")
            sys.stdout.flush()
        gc.enable()  # re-enable garbage collection
        gc.collect()
        print(" ")
        n = 1
        for run in result_list:
            print("Trial " + str(n) + ":\t" + str(run))
            n += 1
        print("-"*50)
        mean = sum(result_list)/len(result_list)
        mean_benchmark = sum(benchmark_list)/len(benchmark_list)
        print("Mean for " + str(repetitions) + " repetitions: " + str(mean) + " sec")
        try:
            import numpy as np
            array = np.array(result_list)
            print( "Standard Deviation: " + str(np.std(array)))
        except ImportError as ie:
            pass
        print("Mean per repetition: " + str(mean/repetitions) + " sec")
        print("Mean for " + str(repetitions) + " of benchmark function:" + str(mean_benchmark) + " sec")
        print("Ratio: " + str(mean/mean_benchmark))
        return result
    return wrapper

def timer_trials_benchmark_1m(func, repetitions=1000000, trials=10):
    @wraps(func)
    def wrapper(*args, **kwargs):
        sys.stdout.write("Starting timed trials of " + func.__name__ + "()")
        sys.stdout.flush()
        result_list = []
        benchmark_list = []
        # disable garbage collection
        gc.collect()
        gc.disable()
        for x in range(trials):
            # test function
            start = time.time()
            for y in range(repetitions):
                func(*args, **kwargs)
            end = time.time()
            result = func(*args, **kwargs)
            result_list.append(end-start)
            # benchmark function
            L = []
            start2 = time.time()
            for j in range(repetitions):
                for i in range(10):
                    L.append(i)
            end2 = time.time()
            benchmark_list.append(end2 - start2)
            sys.stdout.write(".")
            sys.stdout.flush()
        gc.enable()  # re-enable garbage collection
        gc.collect()
        print(" ")
        n = 1
        for run in result_list:
            print("Trial " + str(n) + ":\t" + str(run))
            n += 1
        print("-"*50)
        mean = sum(result_list)/len(result_list)
        mean_benchmark = sum(benchmark_list)/len(benchmark_list)
        print("Mean for " + str(repetitions) + " repetitions: " + str(mean) + " sec")
        try:
            import numpy as np
            array = np.array(result_list)
            print( "Standard Deviation: " + str(np.std(array)))
        except ImportError as ie:
            pass
        print("Mean per repetition: " + str(mean/repetitions) + " sec")
        print("Mean for " + str(repetitions) + " of benchmark function:" + str(mean_benchmark) + " sec")
        print("Ratio: " + str(mean/mean_benchmark))
        return result
    return wrapper

if __name__ == '__main__':
    pass
