import os
import re
import time
import logging
import decimal
import subprocess
import os_tests
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

def init_case(test_instance):
    """init case
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
    """
    # Config file
    cfg_file = os.path.dirname(os_tests.__file__) + "/cfg/os-tests.yaml"
    # Result dir
    with open(cfg_file,'r') as fh:
       keys_data = load(fh, Loader=Loader)
    test_instance.params = keys_data
    results_dir = keys_data['results_dir']
    if not os.path.exists(results_dir):
        os.mkdir(results_dir)
    case_log = test_instance.id() + ".debug"
    log_file = results_dir + '/' + case_log
    if os.path.exists(log_file):
        os.unlink(log_file)
    test_instance.log = logging.getLogger(__name__)
    for handler in logging.root.handlers[:]:
        handler.close()
        logging.root.removeHandler(handler)
    FORMAT = "%(levelname)s:%(message)s"
    logging.basicConfig(level=logging.DEBUG, format=FORMAT, filename=log_file)
    test_instance.log.info("Case id: {}".format(test_instance.id(), test_instance.shortDescription()))
    if os.path.exists(cfg_file):
        test_instance.log.info("{} config file found!".format(cfg_file))

def run_cmd(test_instance,
            cmd,
            expect_ret=None,
            expect_not_ret=None,
            expect_kw=None,
            expect_not_kw=None,
            expect_output=None,
            msg=None,
            cancel_kw=None,
            cancel_not_kw=None,
            cancel_ret=None,
            cancel_not_ret=None,
            timeout=60,
            ):
    """run cmd with/without check return status/keywords and save log

    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        cmd {string} -- cmd to run
        expect_ret {int} -- expected return status
        expect_not_ret {int} -- unexpected return status
        expect_kw {string} -- string expected in output,seperate by ',' if
                              check multi words
        expect_not_kw {string} -- string not expected in output, seperate by
                                  ',' if check multi words
        expect_output {string} -- string exactly the same as output
        cancel_kw {string} -- cancel case if kw not found, seperate by ','
                              if check multi words
        cancel_not_kw {string} -- cancel case if kw found, seperate by ','
                              if check multi words
        cancel_ret {string} -- cancel case if ret code not match, seperate by ','
                              if check multi rets
        cancel_not_ret {string} -- cancel case if ret code found, seperate by ','
                              if check multi rets
        msg {string} -- addtional info to mark cmd run.

    Keyword Arguments:
        check_ret {bool} -- [whether check return] (default: {False})
    """
    if msg is not None:
        test_instance.log.info(msg)
    test_instance.log.info("CMD: %s", cmd)
    status = None
    output = None
    exception_hit = False

    try:
        ret = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, encoding='utf-8')
        status = ret.returncode
        if ret.stdout is not None:
            output = ret.stdout
    except Exception as err:
        test_instance.log.error("Run cmd failed as %s" % err)
        status = None
        exception_hit = True

    if exception_hit:
        test_instance.log.info("Try again")
        test_instance.log.info("Test via uname, if still fail, please make sure no hang or panic in sys")
        try:
            ret = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, encoding='utf-8')
            status = ret.returncode
            if ret.stdout is not None:
               output = ret.stdout
            test_instance.log.info("Return: {}".format(output.decode("utf-8")))
            ret = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, encoding='utf-8')
            status = ret.returncode
            if ret.stdout is not None:
               output = ret.stdout
        except Exception as err:
            test_instance.log.error("Run cmd failed again {}".format(err))
    test_instance.log.info("CMD ret: {} out:{}".format(status, output))
    if expect_ret is not None:
        test_instance.assertEqual(status,
                         expect_ret,
                         msg='ret is %s, expected is %s' %
                         (status, expect_ret))
    if expect_not_ret is not None:
        test_instance.assertNotEqual(
            status,
            expect_not_ret,
            msg='ret is %s, expected not ret is %s' %
            (status, expect_not_ret))
    if expect_kw is not None:
        for key_word in expect_kw.split(','):
            if output.count('\n') > 5:
                find_list = re.findall('\n.*{}.*\n'.format(key_word), output)
            else:
                find_list = re.findall('.*{}.*'.format(key_word), output)
            if len(find_list) > 0:
                test_instance.log.info('expcted "{}" found in "{}"'.format(key_word, ''.join(find_list)))
            else:
                if output.count('\n') > 5:
                    test_instance.fail('expcted "{}" not found in output(check debug log as too many lines)'.format(key_word))
                else:
                    test_instance.fail('expcted "{}" not found in "{}"'.format(key_word,output))
    if expect_not_kw is not None:
        for key_word in expect_not_kw.split(','):
            if output.count('\n') > 5:
                find_list = re.findall('\n.*{}.*\n'.format(key_word), output)
            else:
                find_list = re.findall('.*{}.*'.format(key_word), output)
            if len(find_list) == 0:
                test_instance.log.info('Unexpcted "{}" not found in output'.format(key_word))
            else:
                if output.count('\n') > 5:
                    test_instance.fail('Unexpcted "{}" found in {}'.format(key_word, ''.join(find_list)))
                else:
                    test_instance.fail('Unexpcted "{}" found in "{}"'.format(key_word,output))
    if expect_output is not None:
        test_instance.assertEqual(expect_output,
                         output,
                         msg='exactly expected %s' %
                         (expect_output))
    if cancel_kw is not None:
        cancel_yes = True
        for key_word in cancel_kw.split(','):
            if key_word in output:
                cancel_yes = False
        if cancel_yes:
            test_instance.skipTest("None of %s found, cancel case" % cancel_kw)
    if cancel_not_kw is not None:
        for key_word in cancel_not_kw.split(','):
            if key_word in output:
                test_instance.skipTest("%s found, cancel case" % key_word)
    if cancel_ret is not None:
        cancel_yes = True
        for ret in cancel_ret.split(','):
            if int(ret) == int(status):
                cancel_yes = False
        if cancel_yes:
            test_instance.skipTest("ret code {} not match, cancel case".format(cancel_ret))
    if cancel_not_ret is not None:
        for ret in cancel_not_ret.split(','):
            if int(ret) == int(status):
                test_instance.skipTest("%s ret code found, cancel case" % key_word)
    return output

def compare_nums(test_instance, num1=None, num2=None, ratio=0, msg='Compare 2 nums'):
    '''
    Compare num1 and num2.
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
        num1 {int} -- num1
        num2 {int} -- num2
        ratio {int} -- allow ratio
    Return:
        num1 < num2: return True
        (num1 - num2)/num2*100 > ratio: return False
        (num1 - num2)/num2*100 < ratio: return True
    '''
    num1 = float(num1)
    num2 = float(num2)
    ratio = float(ratio)
    test_instance.log.info(msg)
    if num1 < num2:
        test_instance.log.info("{} less than {}".format(num1, num2))
        return True
    if (num1 - num2)/num2*100 > ratio:
        test_instance.fail("{} vs {} over {}%".format(num1, num2, ratio))
    else:
        test_instance.log.info("{} vs {} less {}%, pass".format(num1, num2, ratio))

def getboottime(test_instance):
    '''
    Get system boot time via "systemd-analyze"
    Arguments:
        test_instance {Test instance} -- unittest.TestCase instance
    '''
    run_cmd(test_instance, "sudo which systemd-analyze", expect_ret=0)
    time_start = int(time.time())
    while True:
        output = run_cmd(test_instance, "sudo systemd-analyze")
        if 'Bootup is not yet finished' not in output:
            break
        time_end = int(time.time())
        run_cmd(test_instance, 'sudo systemctl list-jobs')
        if time_end - time_start > 60:
            test_instance.fail("Bootup is not yet finished after 60s")
        test_instance.log.info("Wait for bootup finish......")
        time.sleep(1)
    cmd = "sudo systemd-analyze blame > /tmp/blame.log"
    run_cmd(test_instance, cmd, expect_ret=0)
    run_cmd(test_instance, "cat /tmp/blame.log", expect_ret=0)
    output = run_cmd(test_instance, "sudo systemd-analyze", expect_ret=0)
    boot_time = re.findall("=.*s", output)[0]
    boot_time = boot_time.strip("=\n")
    boot_time_sec = re.findall('[0-9.]+s', boot_time)[0]
    boot_time_sec = boot_time_sec.strip('= s')
    if 'min' in boot_time:
        boot_time_min = re.findall('[0-9]+min', boot_time)[0]
        boot_time_min = boot_time_min.strip('min')
        boot_time_sec = int(boot_time_min) * 60 + decimal.Decimal(boot_time_sec).to_integral()
    test_instance.log.info(
        "Boot time is {}(s)".format(boot_time_sec))
    return boot_time_sec

def get_all_systemd_service():
    '''
    Get all systemd service from "/usr/lib/systemd/system"
    Arguments:
        None
    Return:
        list of service
    '''
    systemd_dir = "/usr/lib/systemd/system"
    return os.listdir(systemd_dir)
    