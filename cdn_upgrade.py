#!/usr/bin/python2.7
import requests
import json
import os
import time
import re
import linecache
import logging
from subprocess import *
from ipaddress import *

# > title
## > heading
### > section
#some text# > to be developed if needed

#global variables for pre/post configuration of the omd components
##variables for setup.
with open('setup.json', 'r') as setup:
    hostname = json.load(setup)
user_root = hostname["user_root"]
user_ocdn_adm = hostname["user_ocdn_adm"]
domain_name = hostname["domain_name"]   #domain name for OMD setup
hn_salt_master = hostname["hn_salt_master"] #salt master / repo
hn_primary_dir_ctlr = hostname["hn_primary_dir_controller"] #primary director controller
hn_primary_dir_wrkr = hostname["hn_primary_dir_worker"]  #primary director worker
hn_backup_dir_ctlr = hostname["hn_backup_dir_controller"]   #backup director controller
hn_backup_dir_wrkr = hostname["hn_backup_dir_worker"]   #backup director worker
hn_traffic_ops = hostname["hn_traffic_ops"] #traffic ops
hn_traffic_mntr = hostname["hn_traffic_monitor"]    #traffic monitor
hn_traffic_vlt = hostname["hn_traffic_vault"]   #traffic vault
hn_traffic_rtr = hostname["hn_traffic_router"]  #traffic router
hn_traffic_cache = tuple(hostname["hn_traffic_cache"])   #list of caches. order must be mid cache and edge cache
hn_monitor_node = tuple(hostname["hn_monitor_node"])	#list of monitor nodes.
hn_primary_dep_svr = hostname["hn_primary_dep_server"]    #splunk primary deployment server
hn_standby_dep_svr = hostname["hn_standby_dep_server"]    #splunk standby deployment server
hn_primary_sh = hostname["hn_primary_sh"]	#splunk primary summary head
hn_standby_sh = hostname["hn_standby_sh"]	#splunk standby summary head

##variables for general
no_space = ''
a_space = ' '
a_fwd_slash = '/'
a_bkw_slash = '\\'
a_asterisk = '*'
a_double_quote = '"'
a_colon = ':'
a_dash = '-'
a_dot = '.'
a_pipe = '|'
a_amp = '&'
a_underbar = '_'
a_line = '\n'
a_single_quote = '\''
a_at = '@'
a_r_arrow = '>'
a_comma = ','
txt_start = 'start'
txt_complete = 'complete'
txt_delete = 'delete'
txt_install = 'install'
txt_copy = 'copy'
txt_execute = 'execute'
txt_success = 'success'
txt_extract = 'extract'
txt_version = 'version'
txt_current = 'current'
txt_update = 'update'
txt_check = 'check'
txt_upgrade = 'upgrade'
txt_log = 'log'
txt_ssh = 'ssh'
txt_scp = 'scp'
txt_info = 'information'
txt_file = 'file'
txt_source = 'source'
txt_path = 'path'
txt_ip = 'ip'
txt_error = 'error'
txt_format = 'format'
txt_in = 'in'
txt_is = 'is'
txt_not = 'not'
txt_given = 'given'
txt_ing = 'ing'
txt_ed = 'ed'
txt_type = 'type'
txt_the = 'the'
txt_key = 'key'
txt_input = 'input'
txt_for = 'for'
txt_deploy = 'deploy'
txt_list = 'list'
txt_from = 'from'
txt_follow = 'follow'
txt_all = 'all'
txt_component = 'component'
txt_offline = 'offline'
txt_online = 'online'
txt_live = 'live'
txt_status = 'status'
txt_service = 'service'
icon_smiley = ':-)'

##variables for linux commands
cmd_rm = 'rm'
cmd_list = 'ls'
cmd_tail = 'tail'
cmd_tar = 'tar'
cmd_grep = 'grep'
cmd_reboot = 'reboot'
service_sys = 'systemctl'
cmd_tail_1 = -1
cmd_tail_6 = -6
txt_tar_format = 'tgz'
txt_rpm_format = 'rpm'
txt_txt_format = 'txt'
txt_tar_attribute = 'xvfz'
txt_rm_attribute = 'fr'
txt_rpm_attribute = 'U'
txt_rpm_chk_attribute = 'qa'
txt_rpm_flag = 'force'
txt_yum = 'yum'
txt_sudo = 'sudo'
txt_echo = 'echo'

##variables for omd/salt components
cmd_cfgtool = 'omd_cfgtool'
cmd_salt = 'salt'
cmd_salt_1 = 'state.apply'
cmd_salt_2 = 'state.highstate'
cmd_salt_3 = 'cmd.run'
cmd_salt_4 = 'saltutil.clear_cache'
cmd_kubectl = 'kubectl get pod'
salt_role_attribute = '-G'
key_name_component = ('salt', 'director','core','monitor','insights')
key_salt_state_fail = 'Failed'
txt_role = 'role'
txt_parse = 'parse'
txt_highstate = 'highstate'
txt_splunk = 'splunk'
txt_base = 'base'
txt_package = 'package'
txt_traffic = 'traffic'
txt_ops = 'ops'
txt_ort = 'ort'
txt_cache = 'cache'
role_splunk_dep = 'roles:splunk_dep'
role_splunk_master = 'roles:splunk_master'
role_splunk_indexer = 'roles:splunk_indexer'
role_splunk_ssh= 'roles:splunk_summarysearchhead'

##variables for argument
source_ip = '' #mgmt_svr
source_ip_copy = ''
source_path = ''
choose_component_key = ''

##variables for log
upgrade_log_path = ''

##variables for api
server_list_json = ''

#simple logging for script's event
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
logging.basicConfig(level=logging.ERROR, format='%(asctime)s %(levelname)s: %(message)s')

#medthods for procedure, logic, calculation and display
##helper functions for executor / coroutine functions
###helper code block for executing command
def exec_cmd_helper(exec_cmd):
    exec_cmd_status = Popen(exec_cmd, stdin=None, stdout=PIPE, stderr=PIPE, shell=True)
    time.sleep(3)
    out, err = exec_cmd_status.communicate()
    return err if err is True else out

###helper code block for clearing stale/fail jobs in salt
def salt_clear_cache_helper():
    exec_cmd = cmd_salt + a_space + a_single_quote + a_asterisk + a_single_quote + a_space + cmd_salt_4
    exec_cmd_helper(exec_cmd)
    time.sleep(2)

###helper code block for finding package name
def find_pkg_helper(pkg_key):
    txt_pkg_key = re.search(r'([a-z-]+)', pkg_key)
    return str(txt_pkg_key.group()) + '[0-9]' if txt_pkg_key == 'omd-monitor-' else txt_pkg_key.group()

###helper code block for omd_cfgtool
def omd_cfgtool_helper(ul_path):
    exec_cmd = txt_echo + a_space + txt_yum[0] + a_space + a_pipe + a_space + cmd_cfgtool + a_space + 2 * a_dash + txt_upgrade + \
               a_space + 2 * a_r_arrow + a_space + ul_path + a_fwd_slash + cmd_cfgtool + a_underbar + txt_upgrade + a_underbar + \
               txt_log + a_dot + txt_txt_format
    oc = exec_cmd_helper(exec_cmd)
    return oc

###helper code block for finding master/minion error when high-state / role-parse
def log_read_helper(file_name):  # file_read
    fail_catch_lines, fail_id_string, total_fail_lines, total_fail_count, fail_node = [], [], [], [], []
    with open(file_name, 'r') as log_read:
        # print 'cm', file_name
        for line_num, line_txt in enumerate(log_read, start=1):
            fail_catch = re.search(r'(Result:\sFalse)', line_txt)
            if fail_catch:
                fail_catch_lines.append(line_num)
            total_fail_catch = re.search(r'(Failed:\s+)(\d+)', line_txt)
            if total_fail_catch:
                if int(total_fail_catch.group(2)) >= 1:
                    total_fail_count.append(total_fail_catch.group(2))
                    total_fail_lines.append(line_num)
    for i in fail_catch_lines:
        id_line_1 = linecache.getline(file_name, i - 3).strip(' \n')
        id_line_2 = linecache.getline(file_name, i - 2).strip(' \n')
        temp = id_line_2 if id_line_1.startswith('--') else id_line_1
        temp_2 = temp.replace('ID: ', '')
        fail_id_string.append(temp_2)
        linecache.clearcache()
    for i in total_fail_lines:
        temp = linecache.getline(file_name, i - 3).strip(' \n')
        temp_2 = temp.replace('Summary for ', '')
        fail_node.append(temp_2)
        linecache.clearcache()
    return fail_catch_lines, fail_id_string, total_fail_lines, total_fail_count, fail_node

###helper code block for displaying master/minion error when high-state / role-parse
def error_log_helper(exec_cmd):
    aa, bb, cc, dd, ee = log_read_helper(exec_cmd)
    if aa or bb or cc or dd or ee:
        for a, b in zip(aa, bb):
            logging.error('line number: {}; failed id: {}'.format(a, b))
        for c, d, e in zip(cc, dd, ee):
            logging.error('line number: {}; total failed: {}; failed node: {}'.format(c, d, e))

###helper code block for highstate
def high_state_helper(host_name):  # highstate and error checking
    # upgrade_log_path = '/root/omd-os-salt-upgrade-log'
    # hostname based
    exec_cmd = key_name_component[0] + a_space + a_double_quote + host_name + a_dot + domain_name + a_double_quote + a_space + \
               cmd_salt_2 + a_space + 2 * a_r_arrow + a_space + upgrade_log_path + a_fwd_slash + host_name + a_underbar + \
               txt_highstate + a_underbar + txt_log + a_dot + txt_txt_format
    # salt role based
    exec_cmd_2 = key_name_component[0] + a_space + salt_role_attribute + a_space + a_double_quote + host_name + a_double_quote + a_space + \
                 cmd_salt_2 + a_space + 2 * a_r_arrow + a_space + upgrade_log_path + a_fwd_slash + host_name[6:] + a_underbar + \
                 txt_highstate + a_underbar + txt_log + a_dot + txt_txt_format
    # hostname based
    exec_cmd_3 = upgrade_log_path + a_fwd_slash + host_name + a_underbar + txt_highstate + a_underbar + txt_log + a_dot + txt_txt_format
    # salt role based
    exec_cmd_4 = upgrade_log_path + a_fwd_slash + host_name[6:] + a_underbar + txt_highstate + a_underbar + txt_log + a_dot + txt_txt_format
    if role_splunk_dep[:5] in host_name:
        salt_clear_cache_helper()
        exec_cmd_helper(exec_cmd_2)
        time.sleep(5)
        error_log_helper(exec_cmd_4)
    else:
        salt_clear_cache_helper()
        exec_cmd_helper(exec_cmd)
        time.sleep(5)
        error_log_helper(exec_cmd_3)
    return True

###helper code block for skipping lines after first when rpm -qa
def skip_white_line_helper(swl):
    for i in swl.splitlines():
        return i

###helper code block for finding rpm version
def rpm_version_helper(rpm_name):
    exec_cmd = txt_rpm_format + a_space + a_dash + txt_rpm_chk_attribute + a_space + a_pipe + a_space + cmd_grep + a_space + rpm_name
    rpm_ver = exec_cmd_helper(exec_cmd)
    return rpm_ver

###helper code block for compare installed pkg and list pkg in source path
def target_pkg_rstrip_helper(pkg_name):
    return pkg_name.rstrip('.tgz') if pkg_name.endswith(txt_tar_format) else pkg_name.rstrip('.rpm')

###helper code block for compare installed pkg and list pkg in source path
def installed_pkg_rstrip_helper(pkg_name):
    return pkg_name.rstrip('.x86_64')

###helper code block for compare installed pkg and list pkg in source path
def filter_version_string_helper(pkg_name):
    return re.search(r'(\d+)\.(\d+)\.(\d+)\W(\w\d+)', pkg_name)

###helper code block for compare installed pkg and list pkg in source path
def compare_pkg_helper(target_pkg, installed_pkg):
    tp = filter_version_string_helper(target_pkg_rstrip_helper(target_pkg))
    ip = filter_version_string_helper(target_pkg_rstrip_helper(installed_pkg))
    tp_arr = list(tp.group(1,2,3))
    ip_arr = list(ip.group(1,2,3))
    tp_arr.append(tp.group(4).lstrip('b'))
    ip_arr.append(ip.group(4).lstrip('b'))
    return True if tp_arr < ip_arr else False

###helper code block for killing existing director gui session
def restart_dir_gui_helper():
    get_dir_gui_docker_id = "sudo docker ps | awk '/director_gui/ {print $1}'"
    ssh_to_mgmt_linux = txt_ssh  + a_space + user_root + a_at + str(source_ip_copy) + a_space
    ssh_to_dir_wrkr = ssh_to_mgmt_linux + txt_ssh + a_space + user_ocdn_adm + a_at + hn_primary_dir_wrkr + a_space
    cmd_exec_get_dir_gui_docker_id = ssh_to_dir_wrkr + get_dir_gui_docker_id
    dir_gui_docker_id = exec_cmd_helper(cmd_exec_get_dir_gui_docker_id)
    restart_dir_gui = "sudo docker restart " + dir_gui_docker_id.rstrip('\n')
    cmd_exec_restart_dir_gui = ssh_to_dir_wrkr + restart_dir_gui
    restart_dir_gui_status = exec_cmd_helper(cmd_exec_restart_dir_gui)
    return restart_dir_gui_status

###helper code block for cache server list
def list_cache_server_helper():
    director_ui_login = '{"username":"omdadmin","password":"default"}'
    web_protocol = 'https'
    api_base_url = web_protocol + a_colon + 2 * a_fwd_slash + hn_primary_dir_wrkr + a_colon
    api_login = api_base_url + '8099/OMD/login'
    api_server_list = api_base_url + '8099/OMDCdnMgr/server/'
    api_logout = api_base_url + '8099/OMD/logout'
    restart_dir_gui = restart_dir_gui_helper()
    time.sleep(15)
    if restart_dir_gui:
        ui_login_api = requests.post(api_login, data = director_ui_login, verify = False)
        server_list_api = requests.get(api_server_list, cookies = ui_login_api.cookies, verify = False)
        time.sleep(5)
        ui_logout_api = requests.post(api_logout, cookies=ui_login_api.cookies, verify=False)
        global server_list_json
        server_list_json = server_list_api.text

###helper code block for cache admin status
def cache_admin_status_helper(cache_name, admin_status):
    cache_name = str(cache_name)
    admin_status = str(admin_status)
    list_cache_server_helper()
    filter_cache_server = {}
    cache_server_id = {}
    director_ui_login = '{"username":"omdadmin","password":"default"}'
    web_protocol = 'https'
    api_base_url = web_protocol + a_colon + 2 * a_fwd_slash + hn_primary_dir_wrkr + a_colon
    api_login = api_base_url + '8099/OMD/login'
    api_logout = api_base_url + '8099/OMD/logout'
    server_list_obj = json.loads(server_list_json)
    server_list_arr = server_list_obj['servers']
    for cn in server_list_arr:
        if cn['name'] == cache_name:
            filter_cache_server.update(cn)
            cache_server_id = cn['id']
    filter_cache_server.update({"admin_status": admin_status})
    api_server_list = api_base_url + '8099/OMDCdnMgr/server/' + str(cache_server_id)
    restart_dir_gui = restart_dir_gui_helper()
    time.sleep(5)
    ui_login_api = requests.post(api_login, data = director_ui_login, verify = False)
    server_list_api = requests.put(api_server_list, cookies = ui_login_api.cookies, verify = False, data = json.dumps(filter_cache_server))
    logging.info(cache_name + a_space + txt_is + a_space + admin_status) # + a_space + str(server_list_api.status_code)
    ui_logout_api = requests.post(api_logout, cookies = ui_login_api.cookies, verify=False)
    return server_list_api.status_code

###helper code block for cache offline
def cache_offline_helper(cache_name):
    admin_status = 'OFFLINE'
    return cache_admin_status_helper(cache_name, admin_status)

###helper code block for cmd.run for reboot a cache
def reboot_cache_helper(cache_name):
    # check manually and  add domain, sudo
    exec_cmd = cmd_salt + a_space + a_double_quote + cache_name + a_dot + domain_name + a_double_quote + a_space + cmd_salt_3 + \
               a_space + a_double_quote + txt_sudo + a_space + cmd_reboot + a_double_quote + a_space + a_amp
    return exec_cmd_helper(exec_cmd)

###helper code block for cache online
def cache_online_helper(cache_name):
    admin_status = 'ONLINE'
    return cache_admin_status_helper(cache_name, admin_status)

###helper code block for co-routine executor function
def cor_sequence(knc, source_ip, source_path):
    apoc = apply_post_config()
    apoc.next()
    ahs = apply_high_state(pass_send_key = apoc)
    ahs.next()
    apc = apply_pre_config(pass_send_key = ahs)
    apc.next()
    rsrt = rm_source_rpm_tar(pass_send_key = apc)
    rsrt.next()
    sur = show_upgraded_rpm(pass_send_key = rsrt)
    sur.next()
    ur = upgrade_rpm(pass_send_key = sur)
    ur.next()
    scr = show_current_rpm(pass_send_key = ur)
    scr.next()
    uf = untar_file(pass_send_key = scr)
    uf.next()
    sf = scp_file(sip = str(source_ip), spath = source_path, pass_send_key = uf)
    sf.next()
    sslf = source_server_list_file(sip = str(source_ip), spath = source_path, pass_send_key = sf)
    sslf.next()
    process_menu(pass_knc = knc, pass_send_key = sslf)

##helper functions for local main()
###helper code block for source_path
def source_path_helper(sp):
    return 1 if sp[:] == '' or sp[-1] == a_fwd_slash or sp[0] != a_fwd_slash else sp

###printing error statement    
def show_status_helper(source_path = None):
    if source_path == 1:
        logging.error(txt_error + a_space + txt_in + a_space + txt_given + a_space + txt_path + a_space + txt_format)
        return 1
    else:
        return source_path

###heading of code block
def code_block_lable():
    yield 5 * a_colon + a_space + txt_scp + a_space + txt_source + a_space + txt_info + a_space + 5 * a_colon
    yield 5 * a_colon + a_space + txt_input + a_space + txt_the + a_space + txt_key + a_space + txt_from + a_space + txt_follow + txt_ing + \
          a_space + txt_list + a_space + txt_for + a_space + txt_deploy + txt_ing + a_space + txt_the + a_space + txt_component + a_space + 5 * a_colon
    yield 5 * a_colon + a_space + txt_key + a_space + txt_list + a_space + a_colon + a_space + key_name_component[0] + a_comma + a_space + \
          key_name_component[1] + a_comma + a_space + key_name_component[2] + a_comma + a_space + key_name_component[3] + a_comma + a_space + \
          key_name_component[4] + a_comma + a_space + txt_all + a_space + 5 * a_colon
    yield 5 * a_colon + a_space + txt_upgrade + a_space + txt_start + txt_is[-1] + a_space + 5 * a_colon

##executor / coroutine function for local main()
def process_menu(pass_knc = None, pass_send_key = None):
    logging.info('omd-' + pass_knc + a_dash + txt_install + a_space + txt_start + txt_is[-1])
    pass_send_key.send(pass_knc)

def source_server_list_file(sip = None, spath = None, pass_send_key = None):
    while True:
        send_key = (yield)
        monitor_send_key = []
        other_send_key = ''
        exec_cmd = txt_ssh  + a_space + user_root + a_at + sip + a_space + cmd_list + a_space + spath
        if send_key != key_name_component[3]:
            for i in exec_cmd_helper(exec_cmd).splitlines():
                if send_key in i:
                    other_send_key = i
                    break
        else:
            for i in exec_cmd_helper(exec_cmd).splitlines():
                if send_key in i:
                    monitor_send_key.append(i)
        if monitor_send_key:
            pkg_ver_match = 0 # value will be 1 if version is older or same, default is 0
            for i in monitor_send_key:
                if compare_pkg_helper(i, rpm_version_helper(send_key)):
                    logging.error(txt_source + a_space + txt_package + a_space + txt_is + ' older or same ' + txt_version + \
                          ' than ' + txt_install + txt_ed + a_space + txt_version + a_line)
                    pkg_ver_match = 1
            if pkg_ver_match == 0:
                pass_send_key.send(monitor_send_key)
        elif other_send_key:
            if compare_pkg_helper(other_send_key, rpm_version_helper(send_key)):
                logging.error(txt_source + a_space + txt_package + a_space + txt_is + ' older or same ' + txt_version + \
                      ' than ' + txt_install + txt_ed + a_space + txt_version)
            else:
                pass_send_key.send(other_send_key)
        else:
            pass

def scp_file(sip = None, spath = None, pass_send_key = None):
    while True:
        send_key = (yield)
        if isinstance(send_key, list):
            for i in send_key:
                exec_cmd = txt_scp + a_space + user_root + a_at +  sip + a_colon + spath + a_fwd_slash + i + a_space + os.getcwd()
                logging.info(txt_copy + txt_ing + 3 * a_dot + a_space + i)
                exec_cmd_helper(exec_cmd)
            pass_send_key.send(send_key)
        else:
            exec_cmd = txt_scp + a_space + user_root + a_at + sip + a_colon + spath + a_fwd_slash + send_key + a_space + os.getcwd()
            logging.info(txt_copy + txt_ing + 3 * a_dot + a_space + send_key)
            exec_cmd_helper(exec_cmd)
            pass_send_key.send(send_key)

def untar_file(pass_send_key = None):
    while True:
        send_key = (yield)
        monitor_send_key = []
        if isinstance(send_key, list):
            for i in send_key:
                exec_cmd = cmd_tar + a_space + txt_tar_attribute + a_space + i
                logging.info(txt_extract + txt_ing + 3 * a_dot + a_space + i)
                exec_cmd_status = exec_cmd_helper(exec_cmd)
                for j in exec_cmd_status.splitlines():
                    monitor_send_key.append(j)
                    break
            pass_send_key.send(monitor_send_key)
        elif txt_tar_format in send_key:
            exec_cmd = cmd_tar + a_space + txt_tar_attribute + a_space + send_key
            logging.info(txt_extract + txt_ing + 3 * a_dot + a_space + send_key)
            exec_cmd_status = exec_cmd_helper(exec_cmd)
            for i in exec_cmd_status.splitlines():                
                pass_send_key.send(i)
                break
        else:
            pass_send_key.send(send_key)
            
def show_current_rpm(pass_send_key = None):
    while True:
        send_key = (yield)
        monitor_send_key = []
        if isinstance(send_key, list):
            for i in send_key:
                find_pkg = skip_white_line_helper(rpm_version_helper(find_pkg_helper(i)))
                logging.info(txt_current + a_space + txt_rpm_format + a_space + txt_version + a_space + txt_is + 3 * a_dot + a_space + find_pkg)
                monitor_send_key.append(i)
            pass_send_key.send(monitor_send_key)
        else:
            find_pkg = skip_white_line_helper(rpm_version_helper(find_pkg_helper(send_key)))
            logging.info(txt_current + a_space + txt_rpm_format + a_space + txt_version + a_space + txt_is + 3 * a_dot  + a_space + find_pkg)
            pass_send_key.send(send_key)
        
def upgrade_rpm(pass_send_key = None):
    while True:
        send_key = (yield)
        watch_send_key = []
        if isinstance(send_key, list):
            for i in send_key:
                exec_cmd = txt_rpm_format + a_space + a_dash + txt_rpm_attribute + a_space + i + a_space + 2 * a_dash + txt_rpm_flag
                logging.info(txt_upgrade[0:6] + txt_ing + 3 * a_dot + a_space + i)
                exec_cmd_helper(exec_cmd)
                watch_send_key.append(find_pkg_helper(i))
            pass_send_key.send(watch_send_key)
        else:
            exec_cmd = txt_rpm_format + a_space + a_dash + txt_rpm_attribute + a_space + send_key + a_space + 2 * a_dash + txt_rpm_flag
            logging.info(txt_upgrade[0:6] + txt_ing + 3 * a_dot + a_space + send_key)
            exec_cmd_helper(exec_cmd)
            exec_cmd_helper(exec_cmd)
            pass_send_key.send(find_pkg_helper(send_key))

def show_upgraded_rpm(pass_send_key = None):
    while True:
        send_key = (yield)
        monitor_send_key = []
        if isinstance(send_key, list):
            for i in send_key:
                find_pkg = skip_white_line_helper(rpm_version_helper(find_pkg_helper(i)))
                logging.info(txt_upgrade[0:6] + txt_ed + a_space + txt_version + a_space + txt_is + 3 * a_dot + a_space + find_pkg)
                monitor_send_key.append(i)
            pass_send_key.send(monitor_send_key)
        else:
            find_pkg = skip_white_line_helper(rpm_version_helper(find_pkg_helper(send_key)))
            logging.info(txt_upgrade[0:6] + txt_ed + a_space + txt_version + a_space + txt_is + 3 * a_dot + a_space + find_pkg)
            pass_send_key.send(send_key)
        
def rm_source_rpm_tar(pass_send_key = None):
    while True:
        send_key = (yield)
        exec_cmd = cmd_rm + a_space + a_dash + txt_rm_attribute + a_space + a_asterisk + a_dot + txt_tar_format + a_space + a_asterisk + a_dot + \
                   txt_rpm_format
        logging.info(txt_delete[0:5] + txt_ing + 3 * a_dot + a_space + txt_source  + a_space + txt_rpm_format + a_fwd_slash + txt_tar_format + a_space + \
              txt_file)
        exec_cmd_helper(exec_cmd)
        if isinstance(send_key, list):
            monitor_send_key = send_key[0]
            pass_send_key.send(str(monitor_send_key)[0:-1])
        else:
            pass_send_key.send(send_key)

def apply_pre_config(pass_send_key = None):
    while True:
        send_key = (yield)
        global upgrade_log_path
        upgrade_log_path = os.getcwd() + a_fwd_slash + find_pkg_helper(send_key) + txt_upgrade + a_dash + txt_log
        exec_cmd_2 = key_name_component[0] + a_space + a_double_quote + hn_salt_master + a_dot + domain_name + a_double_quote + a_space + \
                     cmd_salt_1 + a_space + txt_role + a_underbar + txt_parse + a_space + 2 * a_r_arrow + a_space + upgrade_log_path + a_fwd_slash + \
                     txt_role + a_underbar + txt_parse + a_underbar + txt_log + a_dot + txt_txt_format
        exec_cmd_3 = upgrade_log_path + a_fwd_slash + txt_role + a_underbar + txt_parse + a_underbar + txt_log + a_dot + txt_txt_format
        if key_name_component[0] in send_key: #salt
            os.mkdir(upgrade_log_path)
            logging.info(txt_execute[:6] + txt_ing + 3 * a_dot + a_space + 'refresh pillar file')
            exec_cmd_helper("salt '*' saltutil.refresh_pillar >> " + upgrade_log_path + "/refresh_pillar_log.txt")
            logging.info(txt_execute[:6] + txt_ing + 3 * a_dot + a_space + cmd_cfgtool + a_space + 2 * a_dash + txt_upgrade)
            omd_cfgtool_helper(upgrade_log_path)
            logging.info(txt_execute[:6] + txt_ing + 3 * a_dot + a_space + exec_cmd_2[0:50])
            exec_cmd_helper(exec_cmd_2)
            error_log_helper(exec_cmd_3)
        elif key_name_component[1] in send_key: #director
            os.mkdir(upgrade_log_path)
            logging.info(txt_execute[:6] + txt_ing + 3 * a_dot + a_space + cmd_cfgtool + a_space + 2 * a_dash + txt_upgrade)
            omd_cfgtool_helper(upgrade_log_path)
        elif key_name_component[2] in send_key: #core
            os.mkdir(upgrade_log_path)
            logging.info(txt_execute[:6] + txt_ing + 3 * a_dot + a_space + cmd_cfgtool + a_space + 2 * a_dash + txt_upgrade)
            omd_cfgtool_helper(upgrade_log_path)
        elif key_name_component[3] in send_key: #monitor and monitor-client
            os.mkdir(upgrade_log_path)
            logging.info(txt_execute[:6] + txt_ing + 3 * a_dot + a_space + cmd_cfgtool + a_space + 2 * a_dash + txt_upgrade)
            omd_cfgtool_helper(upgrade_log_path)
        elif key_name_component[4] in send_key: #insight
            os.mkdir(upgrade_log_path)
            logging.info(txt_execute[:6] + txt_ing + 3 * a_dot + a_space + 'refresh pillar files')
            exec_cmd_helper("salt '*' saltutil.refresh_pillar >> " + upgrade_log_path + "/refresh_pillar_log.txt")
            logging.info(txt_execute[:6] + txt_ing + 3 * a_dot + a_space + exec_cmd_2[0:50])
            exec_cmd_helper(exec_cmd_2)
            logging.info(txt_execute[:6] + txt_ing + 3 * a_dot + a_space + cmd_cfgtool + a_space + 2 * a_dash + txt_upgrade)
            omd_cfgtool_helper(upgrade_log_path)
            error_log_helper(exec_cmd_3)
        pass_send_key.send(send_key)

def apply_high_state(pass_send_key = None):
    while True:
        send_key = (yield)
        if key_name_component[0] in send_key: #salt
            logging.info(txt_execute[:6] + txt_ing + 3 * a_dot + a_space + key_name_component[0] + a_space + txt_highstate)
            high_state_helper(hn_salt_master)
            pass_send_key.send(send_key)
        elif key_name_component[1] in send_key:  #director
            director_server_list = (hn_salt_master, hn_primary_dir_ctlr, hn_backup_dir_ctlr, hn_primary_dir_wrkr, hn_backup_dir_wrkr)
            for dsl in director_server_list:
                logging.info(txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + dsl)
                high_state_helper(dsl)
            pass_send_key.send(send_key)
        elif key_name_component[2] in send_key:  #core
            core_server_list_1 = (hn_salt_master, hn_traffic_ops, hn_traffic_mntr, hn_traffic_vlt, hn_traffic_rtr)
            core_server_list_2 = core_server_list_1 + hn_traffic_cache
            for csl in range(len(core_server_list_2)):
                if csl <= 4:
                    logging.info(txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + core_server_list_2[csl])
                    high_state_helper(core_server_list_2[csl])
                else: ###mid/edge caches offline, highstate, reboot, online
                    logging.info(txt_execute[0:-1] + txt_ing + a_space + txt_cache + a_space + txt_offline + 3 * a_dot + a_space + core_server_list_2[csl])
                    if cache_offline_helper(core_server_list_2[csl]) != 200:
                        logging.error(txt_error + a_space + txt_in + a_space + core_server_list_2[csl] + a_space + txt_offline)
                        pass_send_key.send(False)
                    logging.info(txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + core_server_list_2[csl])
                    high_state_helper(core_server_list_2[csl])
                    logging.info(cmd_reboot + txt_ing + 3 * a_dot + a_space + core_server_list_2[csl])
                    reboot_cache_helper(core_server_list_2[csl])
                    time.sleep(120) #This value will be vary if bare matel node, script to be developed for node alive rather than fixed time
                    logging.info(txt_execute[0:-1] + txt_ing + a_space + txt_cache + a_space + txt_online + 3 * a_dot + a_space + core_server_list_2[csl])
                    if cache_online_helper(core_server_list_2[csl]) != 200:
                        logging.error(txt_error + a_space + txt_in + a_space + core_server_list_2[csl] + a_space + txt_online)
                        pass_send_key.send(False)
            else:
                pass_send_key.send(send_key)
        elif key_name_component[3] in send_key:  # monitor and monitor-client
            monitor_client_list_1 = (hn_primary_dir_ctlr, hn_primary_dir_wrkr,hn_backup_dir_ctlr, \
                                     hn_backup_dir_wrkr, hn_traffic_ops, hn_traffic_mntr,\
                                     hn_traffic_vlt, hn_traffic_rtr)
            monitor_client_list_2 = monitor_client_list_1 + hn_traffic_cache
            exec_cmd_2 = key_name_component[0] + a_space + a_double_quote + hn_salt_master + a_dot + domain_name + a_double_quote + a_space + \
                         cmd_salt_1 + a_space + txt_role + a_underbar + txt_parse + a_space + 2 * a_r_arrow + a_space + upgrade_log_path + a_fwd_slash + \
                         txt_role + a_underbar + txt_parse + a_underbar + txt_log + a_dot + txt_txt_format
            exec_cmd_3 = upgrade_log_path + a_fwd_slash + txt_role + a_underbar + txt_parse + a_underbar + \
                         txt_log + a_dot + txt_txt_format
            logging.info(txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + hn_salt_master)
            high_state_helper(hn_salt_master)
            logging.info(txt_execute[:6] + txt_ing + 3 * a_dot + a_space + exec_cmd_2[0:50])
            exec_cmd_helper(exec_cmd_2)
            error_log_helper(exec_cmd_3)
            for msl in hn_monitor_node:
                logging.info(txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + msl)
                high_state_helper(msl)
                time.sleep(5)
            for mcl in monitor_client_list_2:
                logging.info(txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + mcl)
                high_state_helper(mcl)
                time.sleep(5)
            pass_send_key.send(send_key)
        elif key_name_component[4] in send_key: # insight
            splunk_dep_svr_list = (hn_standby_dep_svr, hn_primary_dep_svr)
            splunk_sh_list = (hn_standby_sh, hn_primary_sh)
            splunk_rest_svr_list = (role_splunk_master, role_splunk_indexer)
            verify_splunk_service = cmd_salt + a_space + salt_role_attribute + a_space + a_double_quote + role_splunk_dep + a_double_quote + a_space + \
                                    cmd_salt_3 + a_space + a_double_quote + service_sys + a_space + txt_status + a_space + txt_splunk + a_double_quote
            verify_splunk_ha = cmd_salt + a_space + salt_role_attribute + a_space + a_double_quote + role_splunk_dep + a_double_quote + a_space + \
                               cmd_salt_3 + a_space + a_double_quote + '/opt/splunk/bin/splunk show splunkd-port -auth admin:default' + a_double_quote
            for sdsl in splunk_dep_svr_list:
                logging.info(txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + sdsl)
                high_state_helper(sdsl)
                time.sleep(5)
            logging.info(txt_check + txt_ing + 3 * a_dot + a_space + txt_splunk + a_space + txt_service + a_space + txt_status)
            print exec_cmd_helper(verify_splunk_service)
            logging.info(txt_check + txt_ing + 3 * a_dot + a_space + txt_splunk + a_space+ 'HA')
            print exec_cmd_helper(verify_splunk_ha)
            for srsl in splunk_rest_svr_list:
                logging.info(txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + srsl)
                high_state_helper(srsl)
                time.sleep(5)
            for sshl in splunk_sh_list:
                logging.info(txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + sshl)
                high_state_helper(sshl)
                time.sleep(5)
            logging.info(txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + role_splunk_ssh)
            high_state_helper(role_splunk_ssh)
            time.sleep(5)
            pass_send_key.send(send_key)

def apply_post_config():
    while True:
        send_key = (yield)        
        if key_name_component[0] in send_key: #salt
            exec_cmd = key_name_component[0] + a_space + a_double_quote + a_asterisk + a_double_quote + a_space + cmd_salt_1 + a_space + \
                       txt_base + a_underbar + txt_package + a_underbar + txt_install + a_space + 2 * a_r_arrow + a_space + upgrade_log_path + a_fwd_slash + \
                       txt_base + a_underbar + txt_package + a_underbar + txt_install + a_underbar + txt_log + a_dot + txt_txt_format
            exec_cmd_2 = upgrade_log_path + a_fwd_slash + txt_base + a_underbar + txt_package + \
                         a_underbar + txt_install + a_underbar + txt_log + a_dot + txt_txt_format
            logging.info(txt_execute[:6] + txt_ing + 3 * a_dot + a_space + exec_cmd[0:41])
            exec_cmd_helper(exec_cmd)
            error_log_helper(exec_cmd_2)
            salt_clear_cache_helper()
        elif key_name_component[1] in send_key: #director
            salt_clear_cache_helper()
        elif key_name_component[2] in send_key: #core
            exec_cmd_helper('rm -fr omd_core_packages')
            salt_clear_cache_helper()
        elif key_name_component[3] in send_key: #monitor and monitor client
            salt_clear_cache_helper()
            logging.info('verify the MONITOR installation manually as OMD Upgrade Guide recommended')
        elif key_name_component[4] in send_key: # insight
            salt_clear_cache_helper()
            logging.info('verify the INSIGHT installation manually as OMD Upgrade Guide recommended')
        logging.info(send_key + txt_install + a_space + txt_is + a_space + txt_complete + txt_ed[-1] + a_line)
#main funtion
def main():
    try:
        block_lable = code_block_lable()
        print ('\x1b[3;34;46m' + block_lable.next() + '\x1b[0m')
        while True:
            try:
                source_ip = IPv4Address(unicode(raw_input(txt_source + a_space + txt_ip + a_space + a_colon + a_space)))
                global source_ip_copy
                source_ip_copy = source_ip
            except AddressValueError as e:
                logging.error(e)
                continue
            break
        source_path = show_status_helper(source_path_helper(raw_input(txt_source + a_space + txt_path + a_space + a_colon + a_space)))
        while source_path == 1:
            source_path = show_status_helper(source_path_helper(raw_input(txt_source + a_space + txt_path + a_space + a_colon + a_space)))
        print ('\x1b[3;34;46m' + block_lable.next() + '\x1b[0m')
        print ('\x1b[3;34;46m' + block_lable.next() + '\x1b[0m')
        choose_component_key = str(raw_input(txt_input + a_space + txt_key + a_space + a_colon + a_space))
        if choose_component_key == txt_all:
            print ('\x1b[3;34;46m' + block_lable.next() + '\x1b[0m')
            for knc in key_name_component:
                cor_sequence(knc, source_ip, source_path)
        elif choose_component_key == key_name_component[0]:
            print ('\x1b[3;34;46m' + block_lable.next() + '\x1b[0m')
            cor_sequence(key_name_component[0], source_ip, source_path)
        elif choose_component_key == key_name_component[1]:
            print('\x1b[3;34;46m' + block_lable.next() + '\x1b[0m')
            for knc in key_name_component[0:2]:
                cor_sequence(knc, source_ip, source_path)
        elif choose_component_key == key_name_component[2]:
            print('\x1b[3;34;46m' + block_lable.next() + '\x1b[0m')
            for knc in key_name_component[0:3]:
                if knc == key_name_component[1]:
                    continue
                cor_sequence(knc, source_ip, source_path)
        elif choose_component_key == key_name_component[3]:
            print('\x1b[3;34;46m' + block_lable.next() + '\x1b[0m')
            for knc in key_name_component[0:4]:
                if knc == key_name_component[1] or knc == key_name_component[2]:
                    continue
                cor_sequence(knc, source_ip, source_path)
        elif choose_component_key == key_name_component[4]:
            print('\x1b[3;34;46m' + block_lable.next() + '\x1b[0m')
            for knc in key_name_component[0:]:
                if knc == key_name_component[1] or knc == key_name_component[2] or knc == key_name_component[3]:
                    continue
                cor_sequence(knc, source_ip, source_path)
        else:
            logging.error(txt_error + a_space + txt_in + a_space + txt_the + a_space + txt_key)
    except:
        pass
    finally:
        pass
        # sys.exit(0)

if __name__ == '__main__':
    main()