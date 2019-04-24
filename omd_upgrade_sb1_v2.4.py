#!/usr/bin/python2.7
import requests
import json
import sys
import os
import time

from subprocess import *
from ipaddress import *

# > title
## > heading
### > section
#some text# > to be developed if needed

#global variables for pre/post configuration of the omd components
##variables for setup.
user_root = 'root'
user_ocdn_adm = 'ocdn_adm'
domain_name = 'bitcoin.com' #domain name for OMD setup
hn_salt_master = 'reposvr'  #salt master / repo
hn_primary_dir_ctlr = 'infernodirctlr'  #primary director controller
hn_primary_dir_wrkr = 'infernodirwrkr'  #primary director worker
hn_backup_dir_ctlr = 'torrentdirctlr'   #backup director controller
hn_backup_dir_wrkr = 'torrentdirwrkr'   #backup director worker
hn_traffic_ops = 'infernotraops'        #traffic ops
hn_traffic_mntr = 'infernotramntr'      #traffic monitor
hn_traffic_vlt = 'infernotravlt'        #traffic vault
hn_traffic_rtr = 'infernotrartr'        #traffic router
hn_traffic_cache = ('infernotramc1', 'infernotramc2', 'infernotraec1', 'infernotraec2') #list of caches. order must be mid cache and edge cache
hn_monitor_node = ('infernomntr1', 'infernomntr2', 'torrentmntr1', 'torrentmntr2')  #list of monitor nodes.
hn_primary_dep_svr = 'torrentdepsvr'    #splunk primary deployment server
hn_standby_dep_svr = 'infernodepsvr'    #splunk standby deployment server
hn_primary_sh = 'torrentsh'     #splunk primary summary head
hn_standby_sh = 'infernosh'     #splunk standby summary head

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
source_path = ''
choose_component_key = ''

##variables for log
upgrade_log_path = ''

##variables for api
server_list_json = ''

#exception functions#

#medthods for procedure, logic, calculation and display
##helper functions for executor / coroutine functions
###helper code block for executing command
def exec_cmd_helper(exec_cmd):
    exec_cmd_status = Popen(exec_cmd, stdin=None, stdout=PIPE, stderr=PIPE, shell=True)
    time.sleep(10)
    out, err = exec_cmd_status.communicate()
    # return (exec_cmd_status.returncode, out, err)
    if err is True:
        return err
    else:
        return out

###helper code block for clearing stale/fail jobs in salt
def salt_clear_cache_helper():
    exec_cmd = cmd_salt = a_space + a_single_quote + a_asterisk + a_single_quote + a_space + cmd_salt_4
    exec_cmd_helper(exec_cmd)
    time.sleep(5)

###helper code block for finding package name
def find_pkg_helper(pkg_key):
    txt_pkg_key = ''
    for i in pkg_key:
        if i.isdigit():
            break
        txt_pkg_key += i
    if txt_pkg_key == 'omd-monitor-':
        return txt_pkg_key + '3'
    else:
        return txt_pkg_key

###helper code block for finding master/minion error when high-state
def log_read_helper(cmd_exec):
    log_read_status = Popen(cmd_exec, stdin=None, stdout=PIPE, stderr=None, shell=True)    
    time.sleep(2)
    log_read_output = log_read_status.stdout.read()
    for i in log_read_output.splitlines():        
        if key_salt_state_fail in i:
            for j in range(len(i) -1, -1, -1):
                if i[j].isdigit() and int(i[j]) >= 1:                    
                    return True

###helper code block for skipping lines after first
def skip_white_line_helper(swl):
    for i in swl.splitlines():
        return i
        break

###helper code block for finding rpm version
def rpm_version_helper(rpm_name):
    exec_cmd = txt_rpm_format + a_space + a_dash + txt_rpm_chk_attribute + a_space + a_pipe + a_space + cmd_grep + a_space + rpm_name
    rpm_ver = exec_cmd_helper(exec_cmd)
    return rpm_ver
    
###helper code block for omd_cfgtool
def omd_cfgtool_helper(ul_path):
    exec_cmd = txt_echo + a_space + txt_yum[0] + a_space + a_pipe + a_space + cmd_cfgtool + a_space + 2 * a_dash + txt_upgrade + \
               a_space + 2 * a_r_arrow + a_space + ul_path + a_fwd_slash + cmd_cfgtool + a_underbar + txt_upgrade + a_underbar + \
               txt_log + a_dot + txt_txt_format
    oc = exec_cmd_helper(exec_cmd)
    return oc
    
###helper code block for highstate
def high_state_helper(host_name):
    exec_cmd = key_name_component[0] + a_space + a_double_quote + host_name + a_dot + domain_name + a_double_quote + a_space + \
               cmd_salt_2 + a_space + 2 * a_r_arrow + a_space + upgrade_log_path + a_fwd_slash + host_name + a_underbar + \
               txt_highstate + a_underbar + txt_log + a_dot + txt_txt_format
    exec_cmd_2 = key_name_component[0] + a_space + salt_role_attribute + a_space + a_double_quote + host_name + a_double_quote + a_space + \
               cmd_salt_2 + a_space + 2 * a_r_arrow + a_space + upgrade_log_path + a_fwd_slash + host_name[6:] + a_underbar + \
               txt_highstate + a_underbar + txt_log + a_dot + txt_txt_format
    exec_cmd_3 = cmd_tail + a_space + str(cmd_tail_6) + a_space + upgrade_log_path + a_fwd_slash + host_name + a_underbar + txt_highstate + a_underbar + \
                 txt_log + a_dot + txt_txt_format
    exec_cmd_4 = cmd_tail + a_space + str(cmd_tail_6) + a_space + upgrade_log_path + a_fwd_slash + host_name[6:] + a_underbar + txt_highstate + a_underbar + \
                 txt_log + a_dot + txt_txt_format
    if role_splunk_dep[:5] in host_name:
        salt_clear_cache_helper()
        exec_cmd_helper(exec_cmd_2)
    else:
        salt_clear_cache_helper()
        exec_cmd_helper(exec_cmd)
    if role_splunk_dep[:5] in host_name:
        if log_read_helper(exec_cmd_4) is True:
            return False
        else:
            return True
    else:
        if log_read_helper(exec_cmd_3) is True:
            return False
        else:
            return True

###helper code block for killing existing director gui session
def restart_dir_gui_helper():
    get_dir_gui_docker_id = "sudo docker ps | awk '/director_gui/ {print $1}'"
    ssh_to_mgmt_linux = txt_ssh  + a_space + user_root + a_at + str(source_ip) + a_space
    print 'mgmt_svr', ssh_to_mgmt_linux
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
    time.sleep(15)
    ui_login_api = requests.post(api_login, data = director_ui_login, verify = False)
    server_list_api = requests.put(api_server_list, cookies = ui_login_api.cookies, verify = False, data = json.dumps(filter_cache_server))
    print cache_name + a_space + txt_is + a_space + admin_status # + a_space + str(server_list_api.status_code)
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
    if sp[:] == '' or sp[-1] == a_fwd_slash or sp[0] != a_fwd_slash:
        return 1
    else:
        return sp

###printing error statement    
def show_status_helper(source_path = None):
    if source_path == 1:
        print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + txt_given + a_space + txt_path + a_space + \
              txt_format
        return 1
    else:
        return source_path

###heading of code block
def code_block_lable():
    yield 5 * a_colon + a_space + txt_scp + a_space + txt_source + a_space + txt_info + a_space + 5 * a_colon
    yield 5 * a_colon + a_space + txt_input + a_space + txt_the + a_space + txt_key + a_space + txt_from + a_space + txt_follow + txt_ing + \
          a_space + txt_list + a_space + txt_for + a_space + txt_deploy + txt_ing + a_space + txt_the + a_space + txt_component + a_space + 5 * a_colon
    yield 5 * a_colon + a_space + txt_key + a_space + txt_list + a_space + a_colon + a_space + key_name_component[
        0] + a_comma + a_space + \
          key_name_component[1] + a_comma + a_space + key_name_component[2] + a_comma + a_space + key_name_component[
              3] + a_comma + a_space + \
          key_name_component[4] + a_comma + a_space + txt_all + a_space + 5 * a_colon
    yield 5 * a_colon + a_space + txt_upgrade + a_space + txt_start + txt_is[-1] + a_space + 5 * a_colon

##executor / coroutine function for local main()
def process_menu(pass_knc = None, pass_send_key = None):
    epoch_time = time.time()
    print txt_start.upper() + txt_is[-1].upper() + a_space + a_at, time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.localtime(epoch_time))
    pass_send_key.send(pass_knc)

def source_server_list_file(sip = None, spath = None, pass_send_key = None):
    while True:
        send_key = (yield)
        monitor_send_key = []
        exec_cmd = txt_ssh  + a_space + user_root + a_at + sip + a_space + cmd_list + a_space + spath
        if send_key != key_name_component[3]:
            for i in exec_cmd_helper(exec_cmd).splitlines():
                if send_key in i:
                    pass_send_key.send (i)
                    break
        else:
            for i in exec_cmd_helper(exec_cmd).splitlines():
                if send_key in i:
                    monitor_send_key.append(i)
            pass_send_key.send (monitor_send_key)

def scp_file(sip = None, spath = None, pass_send_key = None):
    while True:
        send_key = (yield)
        if isinstance(send_key, list):
            for i in send_key:
                exec_cmd = txt_scp + a_space + user_root + a_at +  sip + a_colon + spath + a_fwd_slash + i + a_space + os.getcwd()
                print txt_copy + txt_ing + 3 * a_dot + a_space + i
                exec_cmd_helper(exec_cmd)
            pass_send_key.send(send_key)
        else:
            exec_cmd = txt_scp + a_space + user_root + a_at + sip + a_colon + spath + a_fwd_slash + send_key + a_space + os.getcwd()
            print txt_copy + txt_ing + 3 * a_dot + a_space + send_key
            exec_cmd_helper(exec_cmd)
            pass_send_key.send(send_key)

def untar_file(pass_send_key = None):
    while True:
        send_key = (yield)
        monitor_send_key = []
        if isinstance(send_key, list):
            for i in send_key:
                exec_cmd = cmd_tar + a_space + txt_tar_attribute + a_space + i
                print txt_extract + txt_ing + 3 * a_dot + a_space + i
                exec_cmd_status = exec_cmd_helper(exec_cmd)
                for j in exec_cmd_status.splitlines():
                    monitor_send_key.append(j)
                    break
            pass_send_key.send(monitor_send_key)
        elif txt_tar_format in send_key:
            exec_cmd = cmd_tar + a_space + txt_tar_attribute + a_space + send_key
            print txt_extract + txt_ing + 3 * a_dot + a_space + send_key
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
                print txt_current + a_space + txt_rpm_format + a_space + txt_version + a_space + txt_is, skip_white_line_helper(rpm_version_helper(find_pkg_helper(i)))
                monitor_send_key.append(i)
            pass_send_key.send(monitor_send_key)
        else:
            print txt_current + a_space + txt_rpm_format + a_space + txt_version + a_space + txt_is, skip_white_line_helper(rpm_version_helper(find_pkg_helper(send_key)))
            pass_send_key.send(send_key)
        
def upgrade_rpm(pass_send_key = None):
    while True:
        send_key = (yield)
        monitor_send_key = []
        if isinstance(send_key, list):
            for i in send_key:
                exec_cmd = txt_rpm_format + a_space + a_dash + txt_rpm_attribute + a_space + i + a_space + 2 * a_dash + txt_rpm_flag
                print txt_upgrade[0:6] + txt_ing + 3 * a_dot + a_space + i + a_line, exec_cmd_helper(exec_cmd)                
                monitor_send_key.append(find_pkg_helper(i))
            pass_send_key.send(monitor_send_key)
        else:
            exec_cmd = txt_rpm_format + a_space + a_dash + txt_rpm_attribute + a_space + send_key + a_space + 2 * a_dash + txt_rpm_flag
            print txt_upgrade[0:6] + txt_ing + 3 * a_dot + a_space + send_key + a_line, exec_cmd_helper(exec_cmd)            
            pass_send_key.send(find_pkg_helper(send_key))

def show_upgraded_rpm(pass_send_key = None):
    while True:
        send_key = (yield)
        monitor_send_key = []
        if isinstance(send_key, list):
            for i in send_key:
                print txt_upgrade[0:6] + txt_ed + a_space + txt_version + a_space + txt_is, skip_white_line_helper(rpm_version_helper(find_pkg_helper(i)))
                monitor_send_key.append(i)
            pass_send_key.send(monitor_send_key)
        else:
            print txt_upgrade[0:6] + txt_ed + a_space + txt_version + a_space + txt_is, skip_white_line_helper(rpm_version_helper(find_pkg_helper(send_key)))
            pass_send_key.send(send_key)
        
def rm_source_rpm_tar(pass_send_key = None):
    while True:
        send_key = (yield)
        exec_cmd = cmd_rm + a_space + a_dash + txt_rm_attribute + a_space + a_asterisk + a_dot + txt_tar_format + a_space + a_asterisk + a_dot + \
                   txt_rpm_format
        print txt_delete[0:5] + txt_ing + 3 * a_dot + a_space + txt_source  + a_space + txt_rpm_format + a_fwd_slash + txt_tar_format + a_space + \
              txt_file, exec_cmd_helper(exec_cmd)
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
        exec_cmd_3 = cmd_tail + a_space + str(cmd_tail_6) + a_space + upgrade_log_path + a_fwd_slash + txt_role + a_underbar + txt_parse + a_underbar + \
                     txt_log + a_dot + txt_txt_format
        if key_name_component[0] in send_key: #salt
            os.mkdir(upgrade_log_path)
            print txt_execute[:6] + txt_ing + 3 * a_dot + a_space + 'refresh pillar files' + a_line, exec_cmd_helper("salt '*' saltutil.refresh_pillar")
            print txt_execute[:6] + txt_ing + 3 * a_dot + a_space + cmd_cfgtool + a_space + 2 * a_dash + txt_upgrade, omd_cfgtool_helper(upgrade_log_path)
            print txt_execute[:6] + txt_ing + 3 * a_dot + a_space + exec_cmd_2[0:50], exec_cmd_helper(exec_cmd_2)
            if log_read_helper(exec_cmd_3) is True:
                print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + txt_role + a_underbar + txt_parse + \
                      a_dot + a_space + txt_check + a_space + upgrade_log_path
                pass_send_key.send(False)
            else:
                pass_send_key.send(send_key)
        elif key_name_component[1] in send_key: #director
            os.mkdir(upgrade_log_path)
            print txt_execute[:6] + txt_ing + 3 * a_dot + a_space + cmd_cfgtool + a_space + 2 * a_dash + txt_upgrade, omd_cfgtool_helper(upgrade_log_path)
            pass_send_key.send(send_key)
        elif key_name_component[2] in send_key: #core
            os.mkdir(upgrade_log_path)
            print txt_execute[:6] + txt_ing + 3 * a_dot + a_space + cmd_cfgtool + a_space + 2 * a_dash + txt_upgrade, omd_cfgtool_helper(upgrade_log_path)
            pass_send_key.send(send_key)
        elif key_name_component[3] in send_key: #monitor and monitor-client
            os.mkdir(upgrade_log_path)
            print txt_execute[:6] + txt_ing + 3 * a_dot + a_space + cmd_cfgtool + a_space + 2 * a_dash + txt_upgrade, omd_cfgtool_helper(upgrade_log_path)
            pass_send_key.send(send_key)
        elif key_name_component[4] in send_key: #insight
            os.mkdir(upgrade_log_path)
            print txt_execute[:6] + txt_ing + 3 * a_dot + a_space + 'refresh pillar files' + a_line, exec_cmd_helper("salt '*' saltutil.refresh_pillar")
            print txt_execute[:6] + txt_ing + 3 * a_dot + a_space + exec_cmd_2[0:50], exec_cmd_helper(exec_cmd_2)
            print txt_execute[:6] + txt_ing + 3 * a_dot + a_space + cmd_cfgtool + a_space + 2 * a_dash + txt_upgrade, omd_cfgtool_helper(upgrade_log_path)
            if log_read_helper(exec_cmd_3) is True:
                print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + txt_role + a_underbar + txt_parse + \
                      a_dot + a_space + txt_check + a_space + upgrade_log_path
                #pass_send_key.send(False)
            else:
                pass_send_key.send(send_key)
        
def apply_high_state(pass_send_key = None):
    while True:
        send_key = (yield)
        if key_name_component[0] in send_key: #salt
            print txt_execute[:6] + txt_ing + 3 * a_dot + a_space + key_name_component[0] + a_space + txt_highstate
            if high_state_helper(hn_salt_master) is False: 
                print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + txt_highstate + \
                      a_dot + a_space + txt_check + a_space + upgrade_log_path
                #pass_send_key.send(False)
            else:
                pass_send_key.send(send_key)                
        elif key_name_component[1] in send_key:  #director
            director_server_list = (hn_salt_master, hn_primary_dir_ctlr, hn_backup_dir_ctlr, hn_primary_dir_wrkr, hn_backup_dir_wrkr)
            for dsl in director_server_list:
                print txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + dsl
                if high_state_helper(dsl) is False: 
                    print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + dsl + a_space + txt_highstate + \
                          a_dot + a_space + txt_check + a_space + upgrade_log_path
                    time.sleep(15)
                    #pass_send_key.send(False)
            else:
                pass_send_key.send(send_key)
        elif key_name_component[2] in send_key:  #core
            core_server_list_1 = (hn_salt_master, hn_traffic_ops, hn_traffic_mntr, hn_traffic_vlt, hn_traffic_rtr)
            core_server_list_2 = core_server_list_1 + hn_traffic_cache
            for csl in range(len(core_server_list_2)):
                if csl <= 4:
                    print txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + core_server_list_2[csl]
                    if high_state_helper(core_server_list_2[csl]) is False:
                        print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + core_server_list_2[csl] + a_space + txt_highstate + \
                              a_dot + a_space + txt_check + a_space + upgrade_log_path
                        pass_send_key.send(False)
                else:
                    ###mid/edge caches offline, highstate, reboot, online
                    print txt_execute[0:-1] + txt_ing + a_space + txt_cache + a_space + txt_offline + \
                          3 * a_dot + a_space + core_server_list_2[csl]

                    if cache_offline_helper(core_server_list_2[csl]) != 200:
                        print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + \
                              core_server_list_2[csl] + a_space + txt_offline
                        pass_send_key.send(False)

                    print txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + core_server_list_2[csl]
                    if high_state_helper(core_server_list_2[csl]) is False:
                        print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + core_server_list_2[csl] + a_space + txt_highstate + \
                              a_dot + a_space + txt_check + a_space + upgrade_log_path
                        #pass_send_key.send(False)
                    print cmd_reboot + txt_ing + 3 * a_dot + a_space + core_server_list_2[csl]
                    reboot_cache_helper(core_server_list_2[csl])
                    time.sleep(120) #This value will be vary if bare matel node
                    #script to be developed for node alive rather than fixed time
                    print txt_execute[0:-1] + txt_ing + a_space + txt_cache + a_space + txt_online + \
                    3 * a_dot + a_space + core_server_list_2[csl]
                    if cache_online_helper(core_server_list_2[csl]) != 200:
                        print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + \
                              core_server_list_2[csl] + a_space + txt_online
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
            exec_cmd_3 = cmd_tail + a_space + str(cmd_tail_6) + a_space + upgrade_log_path + a_fwd_slash + txt_role + a_underbar + txt_parse + a_underbar + \
                         txt_log + a_dot + txt_txt_format
            print txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + hn_salt_master
            if high_state_helper(hn_salt_master) is False:
                print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + txt_highstate + \
                a_dot + a_space + txt_check + a_space + upgrade_log_path
                # pass_send_key.send(False)
            print txt_execute[:6] + txt_ing + 3 * a_dot + a_space + exec_cmd_2[0:50], exec_cmd_helper(exec_cmd_2)
            if log_read_helper(exec_cmd_3) is True:
                print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + txt_role + a_underbar + txt_parse + \
                      a_dot + a_space + txt_check + a_space + upgrade_log_path
                #pass_send_key.send(False)
            for msl in hn_monitor_node:
                print txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + msl
                if high_state_helper(msl) is False:
                    print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + msl + a_space + txt_highstate + \
                          a_dot + a_space + txt_check + a_space + upgrade_log_path
                    time.sleep(10)
                    #pass_send_key.send(False)
            for mcl in monitor_client_list_2:
                print txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + mcl
                if high_state_helper(mcl) is False:
                    print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + msl + a_space + txt_highstate + \
                          a_dot + a_space + txt_check + a_space + upgrade_log_path
                    time.sleep(10)
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
                print txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + sdsl
                if high_state_helper(sdsl) is False:
                    print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + sdsl + a_space + txt_highstate + \
                          a_dot + a_space + txt_check + a_space + upgrade_log_path
                    time.sleep(10)
            print 50 * a_asterisk
            print txt_check + txt_ing + 3 * a_dot + a_space + txt_splunk + a_space + txt_service + a_space + txt_status
            print 50 * a_asterisk
            print exec_cmd_helper(verify_splunk_service)
            print 50 * a_asterisk
            print txt_check + txt_ing + 3 * a_dot + a_space + txt_splunk + a_space+ 'HA'
            print 50 * a_asterisk
            print exec_cmd_helper(verify_splunk_ha)
            print 50 * a_asterisk
            for srsl in splunk_rest_svr_list:
                print txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + srsl
                if high_state_helper(srsl) is False:
                    print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + srsl + a_space + txt_highstate + \
                          a_dot + a_space + txt_check + a_space + upgrade_log_path
                    time.sleep(10)
            for sshl in splunk_sh_list:
                print txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + sshl
                if high_state_helper(sshl) is False:
                    print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + sshl + a_space + txt_highstate + \
                          a_dot + a_space + txt_check + a_space + upgrade_log_path
                    time.sleep(10)
            print txt_execute[0:-1] + txt_ing + a_space + txt_highstate + 3 * a_dot + a_space + role_splunk_ssh[6:]
            if high_state_helper(role_splunk_ssh) is False:
                print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + role_splunk_ssh[6:] + a_space + txt_highstate + \
                      a_dot + a_space + txt_check + a_space + upgrade_log_path
                time.sleep(10)
            pass_send_key.send(send_key)

def apply_post_config():
    while True:
        send_key = (yield)        
        if key_name_component[0] in send_key: #salt
            exec_cmd = key_name_component[0] + a_space + a_double_quote + a_asterisk + a_double_quote + a_space + cmd_salt_1 + a_space + \
                       txt_base + a_underbar + txt_package + a_underbar + txt_install + a_space + 2 * a_r_arrow + a_space + upgrade_log_path + a_fwd_slash + \
                       txt_base + a_underbar + txt_package + a_underbar + txt_install + a_underbar + txt_log + a_dot + txt_txt_format
            exec_cmd_2 = cmd_tail + a_space + str(cmd_tail_6) + a_space + upgrade_log_path + a_fwd_slash + txt_base + a_underbar + txt_package + \
                         a_underbar + txt_install + a_underbar + txt_log + a_dot + txt_txt_format
            print txt_execute[:6] + txt_ing + 3 * a_dot + a_space + exec_cmd[0:41], exec_cmd_helper(exec_cmd)
            if log_read_helper(exec_cmd_2) is True:
                print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + txt_highstate + \
                      a_dot + a_space + txt_check + a_space + upgrade_log_path              
            else:
                print ('\x1b[3;30;47m' + key_name_component[0] + a_space + txt_is + a_space + txt_deploy + txt_ed + a_space + icon_smiley + '\x1b[0m')
        elif key_name_component[1] in send_key: #director
            print ('\x1b[3;30;47m' + key_name_component[1] + a_space + txt_is + a_space + txt_deploy + txt_ed + a_space + icon_smiley + '\x1b[0m')
        elif key_name_component[2] in send_key: #core
            print ('\x1b[3;30;47m' + key_name_component[2] + a_space + txt_is + a_space + txt_deploy + txt_ed + a_space + icon_smiley + '\x1b[0m')
        elif key_name_component[3] in send_key: #monitor and monitor client
            print ('\x1b[3;30;47m' + key_name_component[3] + a_space + txt_is + a_space + txt_deploy + txt_ed + a_space + icon_smiley + '\x1b[0m')
            print 'INFO: please verify the MONITOR installation manually as OMD Install and Upgrade Guide recommended'
        elif key_name_component[4] in send_key: # insight
            print('\x1b[3;30;47m' + key_name_component[4] + a_space + txt_is + a_space + txt_deploy + txt_ed + a_space + icon_smiley + '\x1b[0m')
            print 'INFO: please verify the INSIGHT installation manually as OMD Install and Upgrade Guide recommended'
        epoch_time = time.time()
        print txt_complete.upper() + txt_is[-1].upper() + a_space + a_at, time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.localtime(epoch_time))
#main funtion
def main():
    try:
        block_lable = code_block_lable()
        print ('\x1b[3;34;46m' + block_lable.next() + '\x1b[0m')
        while True:
            try:
                source_ip = IPv4Address(unicode(raw_input(txt_source + a_space + txt_ip + a_space + a_colon + a_space)))
            except AddressValueError as e:
                print txt_error.upper() + a_space + a_colon + a_space, e
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
        elif choose_component_key in key_name_component:
            print ('\x1b[3;34;46m' + block_lable.next() + '\x1b[0m')
            cor_sequence(choose_component_key, source_ip, source_path)
        else:
            print txt_error.upper() + a_space + a_colon + a_space + txt_error + a_space + txt_in + a_space + txt_the + a_space + txt_key
    except:
        pass
    finally:
        exec_cmd_helper('rm -fr omd_core_packages')
        salt_clear_cache_helper()
        sys.exit(0)

if __name__ == '__main__':
    main()