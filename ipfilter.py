#!/usr/bin/env python
#-*- coding: utf-8 -*-

import os
import sys
import argparse
import etcd
import time
import socket
import struct
import fcntl
from docker import Client
import subprocess
import shutil
import nmap


def get_local_ip(iface='em1'):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockfd = sock.fileno()
    SIOCGIFADDR = 0x8915
    ifreq = struct.pack('16sH14s', iface, socket.AF_INET, '\x00' * 14)
    try:
        res = fcntl.ioctl(sockfd, SIOCGIFADDR, ifreq)
    except:
        return None
    ip = struct.unpack('16sH2x4s8x', res)[2]
    return socket.inet_ntoa(ip)


def docker_container_all():
    docker_container = docker_client.containers(all=True)
    container_name = []
    container_stop_name = []
    for i in docker_container:
        container_name.append(i['Names'])
    for b in container_name:
        for c in b:
            container_stop_name.append(c)
    return container_stop_name


def docker_container_run():
    docker_container = docker_client.containers()
    container_name = []
    container_stop_name = []
    for i in docker_container:
        container_name.append(i['Names'])
    for b in container_name:
        for c in b:
            container_stop_name.append(c[1::])
    return container_stop_name

if __name__ == "__main__":
    # follow is help info
    p = argparse.ArgumentParser(
        description='It is userful tool to modify docker container firewall')
    p.add_argument("container_name", help="list local docker container name")
    p.add_argument(
        "-l", "--list", help="show container firewall rules", action="store_true")
    p.add_argument(
        "-a", "--add", help="add container firewall rules", action="store_true")
    p.add_argument("-r", "--rm", help="rm container firewall rules")
    p.add_argument(
        "-m", "--mode", choices=["internal", "external"], help="set container firewall mode")
    p.add_argument("-s", "--source",
                   help="source ip view container firewall rules")
    p.add_argument("-sp", "--sport",
                   help="source port view container firewall rules")
    p.add_argument(
        "-d", "--dest", help="destination ip container firewall rules")
    p.add_argument("-dp", "--dport",
                   help="destination port view container firewall rules")
    p.add_argument("-pm", "--portmode",
                   choices=["dynamic", "manual"], help="set container port mode")
    p.add_argument(
        "-e", "--effect", help="effect container  firewall rules", action="store_true")
    p.add_argument("-ap", "--addip", help="add external ip to container")
    p.add_argument("-rp", "--rmip", help="rm external ip to container")
    args = p.parse_args()
    local_ip = get_local_ip('ovs1')
    docker_etcd_key = '/app/docker/'
    etcd_client = etcd.Client(host='127.0.0.1', port=4001)
    docker_client = Client(
        base_url='unix://var/run/docker.sock', version='1.15', timeout=10)
    docker_container_all_name = docker_container_all()
    portmode = 'manual'
    container_ip = ''
    # get container ip
    r = etcd_client.read('%s%s' % (docker_etcd_key, local_ip),
                         recursive=True, sorted=True)
    for child in r.children:
        if child.dir is not True and args.container_name in child.key and 'firewall' not in child.key:
            container_ip = eval(child.value)['Container_ip']
        if len(container_ip) == 0 and args.container_name != "all":
            print 'This container:%s info is not in etcd!' % args.container_name
            sys.exit(1)
    if '/' + args.container_name not in docker_container_all_name and args.container_name != "all":
        print 'local host docker is not container:%s!' % args.container_name
        sys.exit(1)
    if args.list:
     try:
         now_firewall_rule = etcd_client.read(
                '%s%s/firewall/nat-%s' % (docker_etcd_key, local_ip, args.container_name)).value
        except KeyError:
            print 'This container:%s is not firewall rule!'%args.container_name
            sys.exit(1)
    if len(now_firewall_rule) >0:
        now_firewall_rule=eval(now_firewall_rule)
            print 'Follow is container:%s firewall rule!'%args.container_name
        for i in now_firewall_rule:
            print i
    else:
        print 'This container:%s is not firewall rule!'%args.container_name
    sys.exit(1)
    if args.portmode=="dynamic":
    try:
            now_port=etcd_client.read('%s%s/firewall/now_port'%(docker_etcd_key,local_ip)).value
    except KeyError:
        now_port='40000'
        now_port=int(now_port) + 1
    key='%s%s/firewall/now_port'%(docker_etcd_key,local_ip)
        etcd_client.write(key,now_port)
        portmode=args.portmode
    elif args.portmode=="manual":
    if len(args.sport)>0:
            now_port=args.sport
    else:
        print 'no input source port'
    key='%s%s/firewall/now_port'%(docker_etcd_key,local_ip)
    etcd_client.write(key,now_port)
    # add docker container firewall rule
    if args.add:
        if args.mode:
        if args.source:
          if args.source == "all":
            source_ip='0.0.0.0/0.0.0.0'
        else:
            source_ip=args.source
            if args.portmode=="dynamic":
                sport=now_port
        else:
            sport=args.sport
        if args.dport:
            dport=args.dport
        else:
            print 'please input dest port!This port is container local port!'
            sys.exit(1)
        try:
            now_id=len(eval(etcd_client.read('%s%s/firewall/nat-%s'%(docker_etcd_key,local_ip,args.container_name)).value))
        except KeyError:
            now_id='0'
            except SyntaxError:
            now_id='0'
        now_id = int(now_id) + 1
        if args.mode=="internal":
                msg={'Id':now_id,'Mode':args.mode,'Container_name':args.container_name,'Source_ip':source_ip,'Port_mode':portmode,'Source_port':'%s'%sport,'Local_port':dport,'Container_ip':container_ip}
        else:
            if args.dest:
                msg={'Id':now_id,'Mode':args.mode,'Container_name':args.container_name,'Source_ip':source_ip,'Destination_ip':args.dest,'Port_mode':portmode,'Source_port':'%s'%sport,'Local_port':dport,'Container_ip':container_ip}
            else:
                print 'please input destination ip'
                sys.exit(1)
            # add rule to iptables
            try:
                now_firewall_rule=etcd_client.read('%s%s/firewall/nat-%s'%(docker_etcd_key,local_ip,args.container_name)).value
                now_firewall_rule=eval(now_firewall_rule)
            except KeyError:
            now_firewall_rule=[]
        except SyntaxError:
            now_firewall_rule=[]
            for i in now_firewall_rule:
                if msg['Local_port'] == i['Local_port'] and msg['Source_ip'] == i['Source_ip'] and msg['Mode'] == i['Mode'] and msg['Container_name'] == i['Container_name'] and msg['Source_port'] == i['Source_port']:
                    print 'This rule had exist!'
                    sys.exit(1)
            now_firewall_rule.append(msg)
            key='%s%s/firewall/nat-%s'%(docker_etcd_key,local_ip,args.container_name)
            etcd_client.write(key,now_firewall_rule)
            for i in now_firewall_rule:
                print i
    # del exist firewall rule
    if args.rm:
    try:
        now_info=eval(etcd_client.read('%s%s/firewall/nat-%s'%(docker_etcd_key,local_ip,args.container_name)).value)
    except KeyError:
        print 'This Container:%s is not firewall rule!'%args.container_name
        sys.exit(1)
    except SyntaxError:
        print 'This container:%s is not firewall rule!'%args.container_name
        sys.exit(1)
    old_id=[i['Id'] for i in now_info]
    if args.rm != 'all':
        if int(args.rm) not in old_id:
            print 'you input rule id %s is not exit!'%args.rm
            sys.exit(1)
        for i in now_info:
            if int(args.rm) == i['Id']:
                now_info.remove(i)
        print 'Follow is container_name:%s new firewall rule!'%args.container_name
        for i in now_info:
        print i
        key='%s%s/firewall/nat-%s'%(docker_etcd_key,local_ip,args.container_name)
        etcd_client.write(key,now_info)
        sys.exit(0)
    else:
        now_info=''
        key='%s%s/firewall/nat-%s'%(docker_etcd_key,local_ip,args.container_name)
    etcd_client.write(key,now_info)
    print 'This container_name:%s is not  firewall rule!'%args.container_name
    sys.exit(0)
    # effect container firewall rule
    if args.effect:
        # check firewall filter exist
        config_dir='/root/firewall'
        iptables_config='iptables_base.txt'
        if os.path.exists(config_dir) is False:
            os.mkdir(config_dir)
        if os.path.isfile('%s/%s'%(config_dir,iptables_config)) is False:
            print 'no found base iptables config in %s/%s!'%(config_dir,iptables_config)
            sys.exit(1)
    docker_container_run=docker_container_run()
    etcd_exist_firewall=[]
    if args.container_name != "all":
        container_name=args.container_name
        try:
            now_info=eval(etcd_client.read('%s%s/firewall/nat-%s'%(docker_etcd_key,local_ip,args.container_name)).value)
            msg=[]
            msg.append('#follow is container:%s firewall rule\n'%args.container_name)
            for i in now_info:
                if 'Destination_ip' not in i:
                text='-A DOCKER -s %s ! -i ovs2 -p tcp -m tcp --dport %s -j DNAT --to-destination %s:%s'%(i['Source_ip'],i['Source_port'],i['Container_ip'].split('/')[0],i['Local_port'])
                msg.append('%s\n'%text)
                else:
                text='-A DOCKER -s %s -d %s ! -i ovs2 -p tcp -m tcp --dport %s -j DNAT --to-destination %s:%s'%(i['Source_ip'],i['Destination_ip'],i['Source_port'],i['Container_ip'].split('/')[0],i['Local_port'])
                msg.append('%s\n'%text)
        except SyntaxError:
            msg=''
            # wirte container firewall rule
            iptables_new_config='iptables_nat_%s.txt'%args.container_name
            f=open('%s/%s'%(config_dir,iptables_new_config),'w')
            for i in msg:
                f.write(i)
            f.close()
    else:
            r = etcd_client.read('%s%s/firewall'%(docker_etcd_key,local_ip), recursive=True, sorted=True)
            for child in r.children:
                if child.dir is not True and 'nat' in child.key and child.key.split('/')[-1].split('nat-')[-1] in docker_container_run:
                    # etcd_exist_firewall.append(child.key.split('/')[-1].split('nat-')[-1])
            try:
                now_info=eval(etcd_client.read(child.key).value)
                msg=[]
                msg.append('#follow is container:%s firewall rule\n'%child.key.split('/')[-1].split('nat-')[-1])
                for i in now_info:
                if 'Destination_ip' not in i:
                                text='-A DOCKER -s %s ! -i ovs2 -p tcp -m tcp --dport %s -j DNAT --to-destination %s:%s'%(i['Source_ip'],i['Source_port'],i['Container_ip'].split('/')[0],i['Local_port'])
                                msg.append('%s\n'%text)
                        else:
                                text='-A DOCKER -s %s -d %s ! -i ovs2 -p tcp -m tcp --dport %s -j DNAT --to-destination %s:%s'%(i['Source_ip'],i['Destination_ip'],i['Source_port'],i['Container_ip'].split('/')[0],i['Local_port'])
                                msg.append('%s\n'%text)
            except SyntaxError:
            msg=''
            # wirte container firewall rule
            iptables_new_config='iptables_nat_%s.txt'%child.key.split('/')[-1].split('nat-')[-1]
                    f=open('%s/%s'%(config_dir,iptables_new_config),'w')
                    for i in msg:
                    f.write(i)
                    f.close()
    # get now all container firewall rule
    all_firewall_file=[]
    for parent,dirnames,filenames in os.walk(config_dir):
        for filename in filenames:
        if 'iptables_nat' in filename:
            all_firewall_file.append(os.path.join(parent,filename))
        # get iptables base file line
        count = len(open('%s/%s'%(config_dir,iptables_config),'rU').readlines())
        modify_post=int(count)-1
        f=open('%s/%s'%(config_dir,iptables_config),'r+')
        flist=f.readlines()
        flist[modify_post]=''
    f=open
    for i in all_firewall_file:
        f=open(i)
        try:
        container_text=f.read()
        finally:
        f.close()
        flist.append(container_text)
    flist.append('COMMIT\n')
    f=open('%s/temp_iptables.txt'%config_dir,'w')
    for i in flist:
        f.write(i)
    f.close()
    # apply new firewall rule
    shutil.copy('%s/temp_iptables.txt'%config_dir,'/etc/sysconfig/iptables')
    # restart firewall
    firewall_status=((subprocess.Popen("systemctl restart iptables &>>/dev/null && echo 0 || echo 1",shell=True,stdout=subprocess.PIPE)).stdout.readlines()[0]).strip('\n')
    if firewall_status != "0":
        print 'firewall rule has problem!'
        sys.exit(1)
    else:
        print 'config firewall rule is success!'
        sys.exit(0)
    if args.addip:
    if '/' not in args.addip:
        print 'please input ip:netmask!'
        sys.exit(1)
    external_ip=args.addip.split('/')[0]
    external_ip_netmask=args.addip.split('/')[1]
        # nmap ip exist!
    nm = nmap.PortScanner()
    nmap_result=nm.scan(external_ip,'60020')['nmap']['scanstats']['uphosts']
    if int(nmap_result) == 1:
        print 'you input ip:%s is online!'%external_ip
        sys.exit(1)
    try:
        now_ip=eval(etcd_client.read('%s%s/external_ip/%s'%(docker_etcd_key,local_ip,external_ip)).value)
        if now_ip['Container_name'] != args.container_name:
        print 'this is external ip:%s is has used by container:%s.if you want to use it again,please delete this key:%s.'%(args.addip,now_ip['Container_name'],'%s%s/external_ip/%s'%(docker_etcd_key,local_ip,external_ip))
        sys.exit(1)
    except KeyError:
        pass
 
 
    # get device info
    try:
        now_device=etcd_client.read('%s%s/external_ip/device'%(docker_etcd_key,local_ip)).value
    except KeyError:
        now_device='em2:0'
    new_device=now_device.split(':')[0]+':'+str(int(now_device.split(':')[1])+1)
    key='%s%s/external_ip/device'%(docker_etcd_key,local_ip)
    etcd_client.write(key,new_device)
    # add new external ip in localhost
    if int(external_ip_netmask) == 8:
        external_ip_netmask='255.0.0.0'
    elif int(external_ip_netmask) == 16:
        external_ip_netmask='255.255.0.0'
   elif int(external_ip_netmask) == 24:
        external_ip_netmask='255.255.255.0'
    elif int(external_ip_netmask) == 32:
        external_ip_netmask='255.255.255.255'
    else:
        print 'you input netmask %s i can not calculate'%external_ip_netmask
        sys.exit(1)
        add_external_ip_status=((subprocess.Popen("/sbin/ifconfig %s %s netmask %s up &>>/dev/null && echo 0 || echo 1"%(new_device,external_ip,external_ip_netmask),shell=True,stdout=subprocess.PIPE)).stdout.readlines()[0]).strip('\n')
        if add_external_ip_status != "0":
            print 'add external ip:%s is fail!'%args.addip
        sys.exit(1)
        else:
            print 'add external ip:%s is success!'%args.addip
        key='%s%s/external_ip/%s'%(docker_etcd_key,local_ip,external_ip)
        info={'Ip':external_ip,'Netmask':external_ip_netmask,'Container_name':args.container_name,'Device':new_device,'Date':time.strftime('%Y.%m.%d-%T')}
        etcd_client.write(key,info)
        sys.exit(0)
    if args.rmip:
        try:
            now_ip=eval(etcd_client.read('%s%s/external_ip/%s'%(docker_etcd_key,local_ip,args.rmip)).value)
        except KeyError:
            print 'This external ip:%s is not use in etcd!'%args.rmip
        sys.exit(1)
        if now_ip['Container_name'] != args.container_name:
            print 'this is external ip:%s is has used by container:%s.if you want to delete it,please input correct container:%s and external ip:%s.'%(args.rmip,now_ip['Container_name'],now_ip['Container_name'],now_ip['Ip'])
        sys.exit(1)
    # delete use external ip in localhost
    delete_external_ip_status=((subprocess.Popen("/sbin/ifconfig %s  down &>>/dev/null && echo 0 || echo 1"%(now_ip['Device']),shell=True,stdout=subprocess.PIPE)).stdout.readlines()[0]).strip('\n')
    if delete_external_ip_status != "0":
        print 'delete external ip:%s is fail!'%args.rmip
        sys.exit(1)
    else:
        print 'delete external ip:%s is success!'%args.rmip
        key='%s%s/external_ip/%s'%(docker_etcd_key,local_ip,args.rmip)
        etcd_client.delete(key)
        sys.exit(0)
            sys.exit(1)
