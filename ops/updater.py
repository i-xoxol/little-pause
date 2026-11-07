#!/usr/bin/env python3
"""Root-owned controller: fetch public main, sandbox tests, atomically activate.

Repository code is never executed by this root process. Only the fixed build
service runs candidate tests, as an unprivileged user with no network/home.
"""
import argparse
import datetime
import io
import json
import os
from pathlib import Path,PurePosixPath
import re
import secrets
import sqlite3
import subprocess
import tarfile
import time
import urllib.request
from urllib.parse import urlsplit

SHA=re.compile(r'[0-9a-f]{40}\Z')
REQUIRED={'server.py','app.mjs','crypto.mjs','index.html','style.css','favicon.svg','test_server.py','test_crypto.mjs'}
def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def safe_path(name):
    path=PurePosixPath(name)
    if not name or path.is_absolute() or any(p in ('','..','.git') for p in path.parts) or str(path)!=name or any(ord(c)<32 for c in name) or '\\' in name:raise ValueError('Unsafe repository path')
    if name=='release.json' or any(p in ('data','.test-state','backups') for p in path.parts) or name.endswith(('.sqlite3','.db','.pem','.private')):raise ValueError('Private/runtime files cannot be released')
    return path
def parse_tree(raw):
    result=[]
    for entry in raw.split(b'\0'):
        if not entry:continue
        meta,name=entry.split(b'\t',1);mode,kind,blob=meta.decode().split(' ')
        if mode not in ('100644','100755') or kind!='blob' or not SHA.fullmatch(blob):raise ValueError('Only regular source files are supported; no symlinks or submodules')
        name=name.decode('utf-8');safe_path(name);result.append((name,blob))
    if not REQUIRED.issubset({x[0] for x in result}) or len(result)>500:raise ValueError('Required source/tests missing or too many files')
    return result
def atomic_json(path,value):
    temporary=path.with_name(path.name+'.tmp')
    temporary.write_text(json.dumps(value,indent=2)+'\n');os.chmod(temporary,0o600);os.replace(temporary,path)
def read_commit(directory):
    try:
        value=json.loads((directory/'release.json').read_text()).get('commit','')
        return value if SHA.fullmatch(value) else ''
    except (OSError,ValueError,TypeError):return ''
def switch_link(current,target):
    if current.exists() and not current.is_symlink():raise ValueError('Current release must be a symlink')
    link=current.with_name('.current-'+secrets.token_hex(8))
    link.symlink_to(target,target_is_directory=True);os.replace(link,current)
def activate(current,candidate,restart,healthy):
    """Roll back code on failure; user databases are never restored/deleted."""
    previous=current.resolve(strict=True)
    switch_link(current,candidate)
    try:
        restart()
        if not healthy(read_commit(candidate)):raise RuntimeError('Candidate health check failed')
    except Exception:
        switch_link(current,previous)
        restart()
        if not healthy(read_commit(previous)):raise RuntimeError('Candidate failed and previous release failed its health check')
        raise

class Updater:
    def __init__(self,config):
        self.config=config;self.state=Path(config['state']);self.git_dir=self.state/'repository.git';self.current=Path(config['current']);self.releases=Path(config['releases']);self.status_path=self.state/'status.json'
        remote=urlsplit(config['repository'])
        if remote.scheme!='https' or remote.netloc!='github.com' or remote.query or remote.fragment or not re.fullmatch(r'/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?',remote.path):raise ValueError('Use a public github.com HTTPS repository')
        if config.get('branch')!='main':raise ValueError('This installation deploys main only')
        self.env={'PATH':'/usr/bin:/bin','HOME':str(self.state/'git-home'),'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0'}
    def git(self,*args,**kwargs):
        return subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','--git-dir='+str(self.git_dir),*args],env=self.env,check=True,timeout=60,**kwargs)
    def fetch(self):
        self.git('fetch','--no-tags','--depth=1','--force',self.config['repository'],'refs/heads/main:refs/remotes/source/main',stdout=subprocess.DEVNULL)
        value=self.git('rev-parse','refs/remotes/source/main',capture_output=True,text=True).stdout.strip()
        if not SHA.fullmatch(value):raise ValueError('Unexpected revision')
        return value
    def mark(self,**fields):
        try:status=json.loads(self.status_path.read_text())
        except (OSError,ValueError):status={}
        status.update(fields);status['last_check']=utc();status['active_commit']=read_commit(self.current.resolve())
        atomic_json(self.status_path,status)
        print(json.dumps(fields),flush=True)
    def snapshot(self,commit):
        entries=parse_tree(self.git('ls-tree','-rz','--full-tree',commit,capture_output=True).stdout)
        snapshot=[];total=0
        for name,blob in entries:
            size=int(self.git('cat-file','-s',blob,capture_output=True,text=True).stdout)
            total+=size
            if size>2*1024*1024 or total>32*1024*1024:raise ValueError('Release source exceeds configured size limit')
            content=self.git('cat-file','blob',blob,capture_output=True).stdout
            if len(content)!=size:raise ValueError('Source size mismatch')
            snapshot.append((name,content))
        return snapshot
    def archive(self,snapshot):
        target=self.state/'candidate.tar';temporary=target.with_suffix('.tmp')
        with tarfile.open(temporary,'w') as output:
            for name,content in snapshot:
                info=tarfile.TarInfo(name);info.size=len(content);info.mode=0o644;output.addfile(info,io.BytesIO(content))
        os.chmod(temporary,0o644);os.replace(temporary,target)
    def install(self,commit,snapshot):
        target=self.releases/(commit+'-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+secrets.token_hex(3))
        target.mkdir(mode=0o755)
        os.chmod(target,0o755)
        for name,content in snapshot:
            destination=target.joinpath(*safe_path(name).parts);destination.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
            for parent in destination.relative_to(target).parents:
                os.chmod(target/parent,0o755)
            destination.write_bytes(content);os.chmod(destination,0o644)
        (target/'release.json').write_text(json.dumps({'commit':commit,'created':utc()})+'\n');os.chmod(target/'release.json',0o644)
        return target
    def backup(self,commit):
        source=Path(self.config['data'])/'vault.sqlite3'
        if not source.is_file():raise RuntimeError('Existing vault database missing; refusing deployment')
        directory=self.state/'vault-backups';directory.mkdir(exist_ok=True,mode=0o700)
        target=directory/(datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+commit[:12]+'.sqlite3')
        src=sqlite3.connect(source.as_uri()+'?mode=ro',uri=True);dst=sqlite3.connect(target)
        try:src.backup(dst);dst.commit()
        finally:src.close();dst.close()
        os.chmod(target,0o600)
    def restart(self):subprocess.run(['/usr/bin/systemctl','restart',self.config['app_service']],check=True,timeout=30)
    def healthy(self,commit):
        for _ in range(12):
            try:
                request=urllib.request.Request(self.config['health_url'],headers={'User-Agent':'Little-Pause-Auto-Deploy/1.0'})
                with urllib.request.urlopen(request,timeout=5) as response:body=json.load(response)
                if body.get('ok') is True and (not commit or body.get('release')==commit):return True
            except Exception:pass
            time.sleep(1)
        return False
    def run(self,retry=False):
        if not self.git_dir.exists():
            subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null','init','--bare',str(self.git_dir)],env=self.env,check=True,stdout=subprocess.DEVNULL)
        try:candidate=self.fetch()
        except Exception as error:
            self.mark(result='fetch-failed-kept-existing-release',error=type(error).__name__);raise
        if candidate==read_commit(self.current.resolve()):self.mark(result='up-to-date',candidate=candidate);return
        try:old_status=json.loads(self.status_path.read_text())
        except (OSError,ValueError):old_status={}
        if not retry and old_status.get('failed_commit')==candidate and time.time()-old_status.get('failed_at',0)<900:
            self.mark(result='waiting-to-retry-failed-commit',candidate=candidate);return
        try:
            self.mark(result='checking',candidate=candidate)
            snapshot=self.snapshot(candidate);self.archive(snapshot)
            subprocess.run(['/usr/bin/systemctl','start','little-pause-build.service'],check=True,timeout=150)
            if self.fetch()!=candidate:self.mark(result='main-moved-during-checks',candidate=candidate);return
            target=self.install(candidate,snapshot);self.backup(candidate)
            activate(self.current,target,self.restart,self.healthy)
            self.mark(result='deployed',candidate=candidate,deployed_at=utc(),failed_commit=None,failed_at=None)
        except Exception as error:
            self.mark(result='failed-kept-previous-code',candidate=candidate,failed_commit=candidate,failed_at=time.time(),error=type(error).__name__)
            raise

def main():
    import fcntl
    parser=argparse.ArgumentParser();parser.add_argument('--config',default='/etc/little-pause-deploy.json');parser.add_argument('--retry',action='store_true');args=parser.parse_args()
    if os.geteuid()!=0:raise SystemExit('Run the installed updater as root.')
    os.umask(0o077)
    with open('/run/lock/little-pause-update.lock','w') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:return
        Updater(json.loads(Path(args.config).read_text())).run(args.retry)

if __name__=='__main__':main()
