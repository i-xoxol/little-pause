#!/usr/bin/env python3
"""Explicit host installation. Never invoked automatically from a Git commit."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
from urllib.parse import urlsplit

def main():
    if os.geteuid()!=0:raise SystemExit('Run this reviewed installer using sudo.')
    parser=argparse.ArgumentParser()
    parser.add_argument('--repository',required=True)
    parser.add_argument('--origin',required=True)
    parser.add_argument('--data',required=True)
    parser.add_argument('--proxy',required=True)
    parser.add_argument('--http-hosts',default='')
    args=parser.parse_args()
    origin=urlsplit(args.origin)
    if origin.scheme!='https' or not origin.hostname or origin.username or origin.password or origin.query or origin.fragment or origin.path not in ('','/') or not re.fullmatch(r'[A-Za-z0-9.:-]+',origin.netloc):raise SystemExit('Use a plain HTTPS origin.')
    origin=args.origin.rstrip('/');ipaddress.ip_address(args.proxy)
    if args.http_hosts and not re.fullmatch(r'[A-Za-z0-9.:,\[\]-]+',args.http_hosts):raise SystemExit('Invalid HTTP host list.')
    data=Path(args.data).resolve(strict=True)
    if not data.is_dir() or not (data/'vault.sqlite3').is_file():raise SystemExit('Point --data to the existing diary data directory.')
    subprocess.run(['/usr/bin/systemctl','is-active','--quiet','little-pause.service'],check=True)
    for binary in ['/usr/bin/git','/usr/bin/node','/usr/bin/python3']:
        if not Path(binary).is_file():raise SystemExit('Missing prerequisite: '+binary)
    state=Path('/var/lib/little-pause-deploy');state.mkdir(exist_ok=True,mode=0o755);os.chmod(state,0o755)
    (state/'git-home').mkdir(exist_ok=True,mode=0o700)
    builder=Path('/var/lib/little-pause-build')
    try:
        account=pwd.getpwnam('little-pause-build')
        if account.pw_dir!=str(builder) or account.pw_uid>=1000:raise SystemExit('Unexpected existing build user.')
    except KeyError:
        subprocess.run(['/usr/sbin/useradd','--system','--user-group','--home-dir',str(builder),'--create-home','--shell','/usr/sbin/nologin','little-pause-build'],check=True)
        account=pwd.getpwnam('little-pause-build')
    builder.mkdir(exist_ok=True,mode=0o700);os.chown(builder,account.pw_uid,account.pw_gid);os.chmod(builder,0o700)
    installed=Path('/usr/local/lib/little-pause-deploy');installed.mkdir(parents=True,exist_ok=True,mode=0o755);os.chmod(installed,0o755)
    for name in ('updater.py','verify.py'):
        shutil.copyfile(Path(__file__).parent/name,installed/name);os.chmod(installed/name,0o644);os.chown(installed/name,0,0)
    config={'repository':args.repository,'branch':'main','state':str(state),'current':'/opt/little-pause/current','releases':'/opt/little-pause/releases','data':str(data),'app_service':'little-pause.service','health_url':origin+'/healthz'}
    # Validate the URL/branch before installing any active timer.
    from updater import Updater
    Updater(config)
    config_path=Path('/etc/little-pause-deploy.json');config_path.write_text(json.dumps(config,indent=2)+'\n');os.chmod(config_path,0o600)
    dropin=Path('/etc/systemd/system/little-pause.service.d');dropin.mkdir(exist_ok=True)
    (dropin/'release.conf').write_text('[Service]\nEnvironment=JOURNAL_ORIGIN='+origin+'\nEnvironment=JOURNAL_HTTP_HOSTS='+args.http_hosts+'\nEnvironment=JOURNAL_TRUSTED_PROXY='+args.proxy+'\n')
    build='''[Unit]
Description=Test a Little Pause candidate without production access

[Service]
Type=oneshot
User=little-pause-build
Group=little-pause-build
ExecStart=/usr/bin/python3 /usr/local/lib/little-pause-deploy/verify.py
Environment=PYTHONDONTWRITEBYTECODE=1
UMask=0077
PrivateNetwork=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/little-pause-build
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectProc=invisible
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes
KillMode=control-group
TimeoutStartSec=120
MemoryMax=512M
TasksMax=48
'''
    update='''[Unit]
Description=Deploy tested public Little Pause main commits
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/little-pause-deploy/updater.py
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/opt/little-pause /var/lib/little-pause-deploy /run/lock
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
TimeoutStartSec=360
'''
    timer='''[Unit]
Description=Check Little Pause main every two minutes

[Timer]
OnBootSec=90s
OnUnitInactiveSec=2min
RandomizedDelaySec=10s
AccuracySec=10s
Unit=little-pause-update.service

[Install]
WantedBy=timers.target
'''
    for name,content in [('little-pause-build.service',build),('little-pause-update.service',update),('little-pause-update.timer',timer)]:
        path=Path('/etc/systemd/system')/name;path.write_text(content);os.chmod(path,0o644)
    subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True)
    subprocess.run(['/usr/bin/systemctl','enable','--now','little-pause-update.timer'],check=True)
    print('Installed. Run systemctl start little-pause-update.service for the first checked deployment.')

if __name__=='__main__':main()
