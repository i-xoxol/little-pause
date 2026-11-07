#!/usr/bin/env python3
"""Little Pause: single-owner diary. The server never receives the vault key or password."""
import base64
from contextlib import contextmanager
import hashlib
import hmac
import html
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import smtplib
import sqlite3
import ssl
import threading
import time
from email.message import EmailMessage
from email.utils import formatdate,make_msgid,parseaddr
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
ORIGIN = os.environ.get('JOURNAL_ORIGIN','https://journal.example.com').rstrip('/')
PUBLIC_HOST = urlsplit(ORIGIN).netloc
HTTP_HOSTS = tuple(filter(None,os.environ.get('JOURNAL_HTTP_HOSTS','').split(',')))
try: RELEASE = json.loads((ROOT/'release.json').read_text()).get('commit','development')
except (OSError,ValueError): RELEASE = 'development'
ITERATIONS = 600000
USERNAME = re.compile(r'[a-z0-9][a-z0-9_.-]{2,39}\Z')
UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z')

class Problem(Exception):
    def __init__(self, status, message): self.status, self.message = status, message

def digest(value): return hashlib.sha256(value.encode()).hexdigest()
def token(): return secrets.token_urlsafe(32)
def decode(value, size=None, maximum=512000):
    if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9_-]+',value): raise Problem(400,'Invalid encrypted data.')
    try: raw=base64.urlsafe_b64decode(value+'='*((4-len(value)%4)%4))
    except ValueError: raise Problem(400,'Invalid encrypted data.')
    if base64.urlsafe_b64encode(raw).decode().rstrip('=')!=value or len(raw)>maximum or (size is not None and len(raw)!=size): raise Problem(400,'Invalid encrypted data.')
    return raw
def envelope(value, wrapped=False):
    if not isinstance(value,dict) or set(value)!={'v','iv','ct'} or type(value['v']) is not int or value['v']!=1: raise Problem(400,'Invalid encrypted data.')
    decode(value['iv'],12)
    raw=decode(value['ct'],48 if wrapped else None)
    if len(raw)<16: raise Problem(400,'Invalid encrypted data.')
    return json.dumps(value,separators=(',',':'),sort_keys=True)
def username(value):
    value=value.strip().lower() if isinstance(value,str) else ''
    if not USERNAME.fullmatch(value):raise Problem(400,'Choose a username of 3–40 letters, numbers, dots, dashes or underscores.')
    return value
def email_address(value):
    value=value.strip().lower() if isinstance(value,str) else ''
    if len(value)>254 or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}",value): raise Problem(400,'Enter a valid email address.')
    return value
def credential(value,salt):return hashlib.scrypt(decode(value,32),salt=salt,n=131072,r=8,p=1,maxmem=256*1024*1024)

class Mailer:
    def __init__(self, config):self.config=config
    @property
    def ready(self):return bool(self.config.get('from') and self.config.get('host'))
    def send(self,to,kind,secret):
        if not self.ready:raise Problem(503,'Email delivery is temporarily unavailable. Please try again later.')
        setup=kind=='setup'
        action='Finish creating your diary' if setup else 'Reset your diary password'
        link=ORIGIN+('/#setup=' if setup else '/#reset=')+secret
        note='Your recovery key is also required to unlock your existing entries.' if not setup else 'Choose your password in your browser. We will never email it to you.'
        message=EmailMessage()
        message['From']=self.config['from'];message['To']=to;message['Subject']='Little Pause — '+action
        message['Date']=formatdate(localtime=False);message['Message-ID']=make_msgid(domain=parseaddr(self.config['from'])[1].rsplit('@',1)[-1])
        message['Auto-Submitted']='auto-generated'
        message.set_content(f'Hello,\n\n{action}:\n{link}\n\nThis link expires in 30 minutes and can be used once. {note}\n\nIf you did not request this, you can ignore this email.\n\nLittle Pause\nYour private journal\n')
        message.add_alternative(f'<p>Hello,</p><p><a href="{html.escape(link,quote=True)}">{action}</a></p><p>This link expires in 30 minutes and can be used once. {note}</p><p>If you did not request this, you can ignore this email.</p><p>Little Pause<br>Your private journal</p>',subtype='html')
        try:
            host=self.config['host'];port=int(self.config.get('port',25))
            local=ipaddress.ip_address(host).is_loopback if host in ('127.0.0.1','::1') else False
            if self.config.get('tls')=='ssl':connection=smtplib.SMTP_SSL(host,port,timeout=15,context=ssl.create_default_context())
            else:connection=smtplib.SMTP(host,port,timeout=15)
            with connection as smtp:
                smtp.ehlo()
                if not local and self.config.get('tls')!='ssl':smtp.starttls(context=ssl.create_default_context());smtp.ehlo()
                if self.config.get('username'):smtp.login(self.config['username'],self.config['password'])
                smtp.send_message(message)
        except (OSError,smtplib.SMTPException):raise Problem(503,'The email could not be sent. Please try again later.')

class App:
    def __init__(self,data,invite,legacy=None,mailer=None,clock=time.time):
        self.data=Path(data);self.data.mkdir(parents=True,exist_ok=True,mode=0o700)
        os.chmod(self.data,0o700)
        self.db_path=self.data/'vault.sqlite3';self.invite=invite;self.legacy=Path(legacy) if legacy else None
        self.mailer=mailer or Mailer({});self.clock=clock;self.lock=threading.RLock();self.kdf_slots=threading.BoundedSemaphore(2)
        with self.db() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS owner(id INTEGER PRIMARY KEY CHECK(id=1),username TEXT UNIQUE NOT NULL,email TEXT NOT NULL,salt TEXT NOT NULL,vault_id TEXT NOT NULL,auth_salt BLOB NOT NULL,auth_hash BLOB NOT NULL,recovery_salt BLOB NOT NULL,recovery_hash BLOB NOT NULL,password_wrap TEXT NOT NULL,recovery_wrap TEXT NOT NULL,generation INTEGER NOT NULL DEFAULT 1);
            CREATE TABLE IF NOT EXISTS challenges(hash TEXT PRIMARY KEY,kind TEXT NOT NULL,username TEXT,email TEXT,generation INTEGER,expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires REAL NOT NULL,generation INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS entries(id TEXT PRIMARY KEY,version INTEGER NOT NULL,envelope TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS limits(key TEXT PRIMARY KEY,window REAL NOT NULL,count INTEGER NOT NULL);
            ''')
            if not db.execute("SELECT 1 FROM meta WHERE key='enumeration'").fetchone():db.execute("INSERT INTO meta VALUES('enumeration',?)",(token(),))
        os.chmod(self.db_path,0o600)
    @contextmanager
    def db(self):
        db=sqlite3.connect(self.db_path,timeout=10);db.row_factory=sqlite3.Row
        db.execute('PRAGMA secure_delete=ON');db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA foreign_keys=ON')
        try:
            with db:yield db
        finally:db.close()
    def owner(self,db):return db.execute('SELECT * FROM owner WHERE id=1').fetchone()
    def rate(self,key,maximum=8,window=900):
        now=self.clock()
        with self.lock,self.db() as db:
            db.execute('DELETE FROM limits WHERE window<?',(now-86400,))
            row=db.execute('SELECT * FROM limits WHERE key=?',(digest(key),)).fetchone()
            if row and row['window']>now-window:
                if row['count']>=maximum:raise Problem(429,'Too many attempts. Please wait and try again.')
                db.execute('UPDATE limits SET count=count+1 WHERE key=?',(digest(key),))
            else:db.execute('INSERT OR REPLACE INTO limits VALUES(?,?,1)',(digest(key),now))
    def hashed(self,proof):
        decode(proof,32)
        if not self.kdf_slots.acquire(blocking=False):raise Problem(429,'Please try again in a moment.')
        try:
            salt=secrets.token_bytes(16);return salt,credential(proof,salt)
        finally:self.kdf_slots.release()
    def verify(self,proof,salt,expected):
        decode(proof,32)
        if not self.kdf_slots.acquire(blocking=False):raise Problem(429,'Please try again in a moment.')
        try:return hmac.compare_digest(credential(proof,salt),expected)
        finally:self.kdf_slots.release()
    def new_session(self,db,generation):
        secret=token();csrf=token();now=self.clock()
        db.execute('DELETE FROM sessions WHERE expires<?',(now,))
        db.execute('INSERT INTO sessions VALUES(?,?,?,?)',(digest(secret),csrf,now+12*3600,generation))
        return secret,csrf
    def session(self,secret,csrf=None):
        with self.db() as db:
            row=db.execute('SELECT s.* FROM sessions s JOIN owner o ON s.generation=o.generation WHERE s.hash=? AND s.expires>?',(digest(secret),self.clock())).fetchone()
            if not row:raise Problem(401,'Sign in to unlock your diary.')
            if csrf is not None and not hmac.compare_digest(row['csrf'],csrf):raise Problem(403,'Please refresh and try again.')
            return dict(row)
    def bundle(self,row):return {'username':row['username'],'email':row['email'],'salt':row['salt'],'vaultId':row['vault_id'],'passwordWrap':json.loads(row['password_wrap']),'recoveryWrap':json.loads(row['recovery_wrap']),'iterations':ITERATIONS}
    def challenge(self,db,secret,kind):
        if not isinstance(secret,str) or len(secret)!=43:raise Problem(400,'This link is invalid or has expired. Request a new one.')
        row=db.execute('SELECT * FROM challenges WHERE hash=? AND kind=? AND expires>?',(digest(secret),kind,self.clock())).fetchone()
        if not row:raise Problem(400,'This link is invalid or has expired. Request a new one.')
        return row
    def legacy_rows(self):
        if not self.legacy or not self.legacy.exists():return []
        db=sqlite3.connect('file:'+str(self.legacy)+'?mode=ro',uri=True)
        try:
            db.row_factory=sqlite3.Row;return [dict(x) for x in db.execute('SELECT * FROM entries ORDER BY id')]
        finally:db.close()
    def handle(self,path,body,session='',csrf='',peer='local'):
        if path=='bootstrap':
            with self.db() as db:return {'registered':bool(self.owner(db)),'emailReady':self.mailer.ready,'iterations':ITERATIONS}
        if path=='setup/start':
            self.rate('setup:'+peer,5)
            if not isinstance(body.get('invite'),str) or not hmac.compare_digest(body['invite'].strip(),self.invite):raise Problem(403,'Check your invitation code. It is needed only for the first registration.')
            name=username(body.get('username'));email=email_address(body.get('email'));secret=token()
            with self.lock,self.db() as db:
                if self.owner(db):raise Problem(409,'This diary already has an owner. Please sign in.')
                db.execute('DELETE FROM challenges WHERE expires<?',(self.clock(),))
                db.execute('INSERT INTO challenges VALUES(?,?,?,?,?,?)',(digest(secret),'setup',name,email,0,self.clock()+1800))
            try:self.mailer.send(email,'setup',secret)
            except Exception:
                with self.db() as db:db.execute('DELETE FROM challenges WHERE hash=?',(digest(secret),))
                raise
            return {'ok':True}
        if path=='setup/inspect':
            self.rate('inspect:'+peer,40)
            with self.db() as db:
                row=self.challenge(db,body.get('token'),'setup')
                if self.owner(db):raise Problem(409,'This diary already has an owner.')
                return {'username':row['username'],'email':row['email']}
        if path=='setup/complete':
            self.rate('complete:'+peer,8)
            vault=body.get('vaultId','')
            if not UUID.fullmatch(vault):raise Problem(400,'Invalid vault.')
            decode(body.get('salt'),32);pw=envelope(body.get('passwordWrap'),True);rw=envelope(body.get('recoveryWrap'),True)
            auth_salt,auth_hash=self.hashed(body.get('auth'));rec_salt,rec_hash=self.hashed(body.get('recoveryAuth'))
            with self.lock,self.db() as db:
                db.execute('BEGIN IMMEDIATE')
                c=self.challenge(db,body.get('token'),'setup')
                if self.owner(db):raise Problem(409,'This diary already has an owner.')
                db.execute('INSERT INTO owner(id,username,email,salt,vault_id,auth_salt,auth_hash,recovery_salt,recovery_hash,password_wrap,recovery_wrap) VALUES(1,?,?,?,?,?,?,?,?,?,?)',(c['username'],c['email'],body['salt'],vault,auth_salt,auth_hash,rec_salt,rec_hash,pw,rw))
                db.execute('DELETE FROM challenges');secret,csrf=self.new_session(db,1)
            return {'ok':True,'csrf':csrf,'legacyCount':len(self.legacy_rows())},secret
        if path=='auth/salt':
            self.rate('salt:'+peer,80)
            name=username(body.get('username'))
            with self.db() as db:
                owner=self.owner(db);key=db.execute("SELECT value FROM meta WHERE key='enumeration'").fetchone()[0]
                fake=base64.urlsafe_b64encode(hmac.new(key.encode(),name.encode(),hashlib.sha256).digest()).decode().rstrip('=')
                return {'salt':owner['salt'] if owner and owner['username']==name else fake,'iterations':ITERATIONS}
        if path=='auth/login':
            self.rate('login:'+peer,12)
            name=username(body.get('username'))
            with self.db() as db:owner=self.owner(db)
            valid=self.verify(body.get('auth'),owner['auth_salt'] if owner else bytes(16),owner['auth_hash'] if owner else bytes(32))
            if not owner or name!=owner['username'] or not valid:raise Problem(401,'The username or password is incorrect.')
            with self.lock,self.db() as db:
                current=self.owner(db)
                if current['generation']!=owner['generation']:raise Problem(401,'Please sign in again.')
                secret,csrf=self.new_session(db,owner['generation'])
            return {**self.bundle(owner),'csrf':csrf,'legacyCount':len(self.legacy_rows())},secret
        if path=='auth/recovery/start':
            self.rate('reset:'+peer,4)
            email=email_address(body.get('email'))
            if not self.mailer.ready:raise Problem(503,'Email delivery is temporarily unavailable. Please try again later.')
            with self.db() as db:owner=self.owner(db)
            if owner and hmac.compare_digest(email,owner['email']):
                self.rate('reset-owner',4)
                secret=token()
                with self.db() as db:db.execute('INSERT INTO challenges VALUES(?,?,?,?,?,?)',(digest(secret),'reset',owner['username'],email,owner['generation'],self.clock()+1800))
                try:self.mailer.send(email,'reset',secret)
                except Exception:
                    with self.db() as db:db.execute('DELETE FROM challenges WHERE hash=?',(digest(secret),))
                    raise
            return {'ok':True,'message':'If this is your verified email, a recovery link will arrive shortly.'}
        if path=='auth/recovery/inspect':
            self.rate('inspect:'+peer,40)
            with self.db() as db:
                c=self.challenge(db,body.get('token'),'reset');owner=self.owner(db)
                if not owner or c['generation']!=owner['generation']:raise Problem(400,'This link has expired. Request a new one.')
                return {'username':owner['username'],'vaultId':owner['vault_id'],'recoveryWrap':json.loads(owner['recovery_wrap'])}
        if path=='auth/recovery/complete':
            self.rate('recover:'+peer,8)
            decode(body.get('salt'),32);pw=envelope(body.get('passwordWrap'),True)
            with self.db() as db:c=self.challenge(db,body.get('token'),'reset');owner=self.owner(db)
            if not owner or c['generation']!=owner['generation'] or not self.verify(body.get('recoveryAuth'),owner['recovery_salt'],owner['recovery_hash']):raise Problem(400,'Check your recovery key and request a fresh email link.')
            auth_salt,auth_hash=self.hashed(body.get('auth'))
            with self.lock,self.db() as db:
                db.execute('BEGIN IMMEDIATE');self.challenge(db,body['token'],'reset')
                if self.owner(db)['generation']!=owner['generation']:raise Problem(400,'This link has expired.')
                db.execute('UPDATE owner SET salt=?,auth_salt=?,auth_hash=?,password_wrap=?,generation=generation+1 WHERE id=1',(body['salt'],auth_salt,auth_hash,pw))
                db.execute('DELETE FROM sessions');db.execute('DELETE FROM challenges')
            return {'ok':True}
        self.session(session,csrf if path not in ('session','entries','legacy') else None)
        if path=='session':
            with self.db() as db:owner=self.owner(db)
            return {**self.bundle(owner),'csrf':self.session(session)['csrf'],'legacyCount':len(self.legacy_rows())}
        if path=='auth/logout':
            with self.db() as db:db.execute('DELETE FROM sessions WHERE hash=?',(digest(session),))
            return {'ok':True},''
        if path=='auth/password':
            self.rate('change:'+peer,8)
            with self.db() as db:owner=self.owner(db)
            if not self.verify(body.get('oldAuth'),owner['auth_salt'],owner['auth_hash']):raise Problem(401,'The current password is incorrect.')
            decode(body.get('salt'),32);pw=envelope(body.get('passwordWrap'),True);a,h=self.hashed(body.get('auth'))
            with self.lock,self.db() as db:
                db.execute('BEGIN IMMEDIATE')
                if self.owner(db)['generation']!=owner['generation']:raise Problem(409,'Please sign in again.')
                db.execute('UPDATE owner SET salt=?,auth_salt=?,auth_hash=?,password_wrap=?,generation=generation+1',(body['salt'],a,h,pw))
                db.execute('DELETE FROM sessions');db.execute('DELETE FROM challenges');secret,csrf=self.new_session(db,owner['generation']+1)
            return {'ok':True,'csrf':csrf},secret
        if path=='entries':
            with self.db() as db:return {'entries':[{'id':r['id'],'version':r['version'],'envelope':json.loads(r['envelope'])} for r in db.execute('SELECT * FROM entries')]}
        if path=='entry/save':
            ident=body.get('id','');version=body.get('version');data=envelope(body.get('envelope'))
            if not UUID.fullmatch(ident) or type(version) is not int or not 0<=version<2**31:raise Problem(400,'Invalid entry.')
            with self.lock,self.db() as db:
                db.execute('BEGIN IMMEDIATE');row=db.execute('SELECT version FROM entries WHERE id=?',(ident,)).fetchone()
                if (row['version'] if row else 0)!=version:raise Problem(409,'This entry changed on another device. Save your version as a new entry.')
                db.execute('INSERT INTO entries VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET version=excluded.version,envelope=excluded.envelope',(ident,version+1,data))
            return {'version':version+1}
        if path=='entry/delete':
            with self.lock,self.db() as db:
                result=db.execute('DELETE FROM entries WHERE id=? AND version=?',(body.get('id'),body.get('version')))
                if not result.rowcount:raise Problem(409,'The entry changed. Refresh before deleting it.')
            return {'ok':True}
        if path=='legacy':return {'entries':self.legacy_rows()}
        if path=='legacy/import':
            rows=body.get('entries')
            if not isinstance(rows,list) or len(rows)>10000:raise Problem(400,'Invalid import.')
            for r in rows:
                if not isinstance(r,dict) or not UUID.fullmatch(r.get('id','')):raise Problem(400,'Invalid import.')
                envelope(r.get('envelope'))
            if len(set(r['id'] for r in rows))!=len(rows):raise Problem(400,'Invalid import.')
            if not self.legacy or not self.legacy.exists():raise Problem(409,'Your entries have already been imported.')
            with self.lock,self.db() as db:
                db.execute('ATTACH DATABASE ? AS legacy',(str(self.legacy),));db.execute('PRAGMA legacy.secure_delete=ON');db.execute('BEGIN IMMEDIATE')
                ids=[r[0] for r in db.execute('SELECT id FROM legacy.entries ORDER BY id')]
                if not ids or ids!=[r.get('legacyId') for r in rows]:raise Problem(409,'The original entries changed. Start the import again.')
                for r in rows:db.execute('INSERT INTO entries VALUES(?,1,?)',(r['id'],envelope(r['envelope'])))
                db.execute('DELETE FROM legacy.entries');db.commit();db.execute('VACUUM legacy')
            return {'ok':True,'imported':len(rows)}
        raise Problem(404,'Not found.')

GET_ROUTES={'bootstrap','session','entries','legacy'}
ASSETS={'/':'index.html','/app.mjs':'app.mjs','/crypto.mjs':'crypto.mjs','/style.css':'style.css','/favicon.svg':'favicon.svg'}
def make_handler(app,dev=False,trusted=()):
    class Handler(BaseHTTPRequestHandler):
        server_version='LittlePause';sys_version='';timeout=20
        def log_message(self,*args):pass
        def reply(self,status,data,kind='application/json; charset=utf-8',cookie=None,location=None):
            raw=json.dumps(data,separators=(',',':')).encode() if isinstance(data,(dict,list)) else data.encode() if isinstance(data,str) else data
            self.send_response(status);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(raw)))
            for k,v in {'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','X-Frame-Options':'DENY','Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",'Permissions-Policy':'camera=(), microphone=(), geolocation=()'}.items():self.send_header(k,v)
            if not dev:self.send_header('Strict-Transport-Security','max-age=31536000')
            if location:self.send_header('Location',location)
            if cookie is not None:
                name='lp_test_session' if dev else '__Host-lp_session'
                self.send_header('Set-Cookie',f'{name}={cookie}; Path=/; HttpOnly; SameSite=Strict; Max-Age={43200 if cookie else 0}'+('' if dev else '; Secure'))
            self.end_headers()
            if self.command!='HEAD':self.wfile.write(raw)
        def run_request(self):
            path=urlsplit(self.path).path
            host=self.headers.get('Host','')
            if not dev and host not in (PUBLIC_HOST,*HTTP_HOSTS):raise Problem(421,'Invalid host.')
            secure=dev or (self.client_address[0] in trusted and self.headers.get('X-Forwarded-Proto')=='https')
            if not secure:
                if self.command in ('GET','HEAD'):return self.reply(308,'Use HTTPS.','text/plain',location=ORIGIN+(path if path.strip('/')==app.invite else '/'))
                raise Problem(403,'Use the secure HTTPS address.')
            if path.strip('/')==app.invite and self.command in ('GET','HEAD'):
                return self.reply(303,'','text/plain',location='/')
            if path in ASSETS and self.command in ('GET','HEAD'):
                file=ROOT/ASSETS[path];kind={'html':'text/html; charset=utf-8','mjs':'text/javascript; charset=utf-8','css':'text/css; charset=utf-8','svg':'image/svg+xml'}[file.suffix[1:]]
                return self.reply(200,file.read_bytes(),kind)
            if path=='/healthz' and self.command in ('GET','HEAD'):return self.reply(200,{'ok':True,'release':RELEASE})
            if not path.startswith('/api/'):raise Problem(404,'Not found.')
            route=path[5:]
            if self.command!=('GET' if route in GET_ROUTES else 'POST'):raise Problem(405,'Method not allowed.')
            if self.headers.get('Sec-Fetch-Site')=='cross-site':raise Problem(403,'Forbidden.')
            if self.command=='POST':
                expected=f'http://{host}' if dev else ORIGIN
                if self.headers.get('Origin')!=expected:raise Problem(403,'Forbidden.')
                if self.headers.get('Content-Type','').split(';')[0]!='application/json':raise Problem(415,'Use JSON.')
                try:
                    n=int(self.headers.get('Content-Length','0'))
                    if not 0<n<=4*1024*1024:raise ValueError()
                    body=json.loads(self.rfile.read(n))
                    if not isinstance(body,dict):raise ValueError()
                except (ValueError,TypeError):raise Problem(400,'Invalid request.')
            else:body={}
            cookie=SimpleCookie()
            try:cookie.load(self.headers.get('Cookie',''))
            except Exception:raise Problem(400,'Invalid request.')
            name='lp_test_session' if dev else '__Host-lp_session'
            session=cookie[name].value if name in cookie else ''
            peer=self.headers.get('CF-Connecting-IP',self.client_address[0]) if self.client_address[0] in trusted else self.client_address[0]
            result=app.handle(route,body,session,self.headers.get('X-CSRF-Token',''),peer)
            if isinstance(result,tuple):self.reply(200,result[0],cookie=result[1])
            else:self.reply(200,result)
        def dispatch(self):
            try:self.run_request()
            except Problem as e:self.reply(e.status,{'error':e.message})
            except (BrokenPipeError,ConnectionResetError,TimeoutError):pass
            except Exception as e:
                print('Request failed:',type(e).__name__,flush=True)
                self.reply(500,{'error':'Something went wrong. Your words are still in your browser. Please try again.'})
        do_GET=dispatch;do_POST=dispatch;do_HEAD=dispatch;do_PUT=dispatch;do_DELETE=dispatch;do_OPTIONS=dispatch
    return Handler

if __name__=='__main__':
    os.umask(0o077)
    data=Path(os.environ.get('JOURNAL_DATA',str(ROOT/'data')))
    config_path=Path(os.environ.get('JOURNAL_MAIL_CONFIG',str(data/'mail.json')))
    config=json.loads(config_path.read_text()) if config_path.exists() else {}
    invite=(data/'setup-code').read_text().strip()
    app=App(data,invite,data/'journal.sqlite3',Mailer(config))
    dev=os.environ.get('JOURNAL_DEV')=='1'
    trusted=tuple(filter(None,os.environ.get('JOURNAL_TRUSTED_PROXY','').split(',')))
    server=ThreadingHTTPServer(('127.0.0.1' if dev else '0.0.0.0',int(os.environ.get('JOURNAL_PORT','8095'))),make_handler(app,dev,trusted))
    server.daemon_threads=True
    print('Little Pause secure journal ready.',flush=True)
    server.serve_forever()
