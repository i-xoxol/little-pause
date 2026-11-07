import base64
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
import urllib.request
import urllib.error
import uuid
from http.server import ThreadingHTTPServer
from server import App,Problem,make_handler,ORIGIN,PUBLIC_HOST

def blob(n):return base64.urlsafe_b64encode(bytes(range(n))).decode().rstrip('=')
WRAP={'v':1,'iv':blob(12),'ct':blob(48)}
ENTRY={'v':1,'iv':blob(12),'ct':blob(80)}
class Mail:
    ready=True
    def __init__(self):self.messages=[]
    def send(self,to,kind,secret):self.messages.append((to,kind,secret))
class Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.mail=Mail();self.now=[1000.0]
        self.legacy=self.root/'legacy.sqlite3'
        with sqlite3.connect(self.legacy) as db:
            db.execute('CREATE TABLE entries(id INTEGER PRIMARY KEY,created TEXT,previous TEXT,next TEXT,note TEXT)')
            db.execute('INSERT INTO entries VALUES(1,?,?,?,?)',('2026-11-06','PRIVATE LEGACY SENTINEL','a','b'))
        db.close()
        self.app=App(self.root/'data','private-invite',self.legacy,self.mail,lambda:self.now[0])
    def tearDown(self):self.temp.cleanup()
    def assertProblem(self,status,fn):
        with self.assertRaises(Problem) as c:fn()
        self.assertEqual(c.exception.status,status)
    def create(self):
        self.app.handle('setup/start',{'invite':'private-invite','username':'anna','email':'anna@example.test'})
        setup=self.mail.messages[-1][2]
        data={'token':setup,'vaultId':str(uuid.uuid4()),'salt':blob(32),'auth':blob(32),'recoveryAuth':blob(32),'passwordWrap':WRAP,'recoveryWrap':WRAP}
        result,self.session=self.app.handle('setup/complete',data);self.csrf=result['csrf'];return data
    def test_private_invite_email_and_single_owner(self):
        self.assertProblem(403,lambda:self.app.handle('setup/start',{'invite':'wrong','username':'anna','email':'anna@example.test'}))
        data=self.create();self.assertEqual(self.mail.messages[0][:2],('anna@example.test','setup'))
        self.assertProblem(400,lambda:self.app.handle('setup/complete',data))
        self.assertProblem(409,lambda:self.app.handle('setup/start',{'invite':'private-invite','username':'second','email':'other@example.test'}))
    def test_auth_session_csrf_and_ciphertext_only(self):
        data=self.create();self.assertProblem(401,lambda:self.app.handle('entries',{}))
        self.assertProblem(401,lambda:self.app.handle('auth/login',{'username':'anna','auth':blob(31)+'A'}))
        login,session=self.app.handle('auth/login',{'username':'anna','auth':data['auth']})
        ident=str(uuid.uuid4());body={'id':ident,'version':0,'envelope':ENTRY,'title':'PRIVATE TEXT NEVER STORED'}
        self.assertProblem(403,lambda:self.app.handle('entry/save',body,session,'wrong'))
        self.assertEqual(self.app.handle('entry/save',body,session,login['csrf']),{'version':1})
        self.assertProblem(409,lambda:self.app.handle('entry/save',body,session,login['csrf']))
        self.assertNotIn(b'PRIVATE TEXT NEVER STORED',self.app.db_path.read_bytes())
        self.assertEqual(self.app.handle('entries',{},session)['entries'][0]['version'],1)
        self.app.handle('auth/logout',{},session,login['csrf']);self.assertProblem(401,lambda:self.app.handle('entries',{},session))
    def test_email_and_recovery_both_required_and_one_use(self):
        self.create();self.app.handle('auth/recovery/start',{'email':'anna@example.test'});secret=self.mail.messages[-1][2]
        info=self.app.handle('auth/recovery/inspect',{'token':secret});self.assertEqual(info['username'],'anna')
        body={'token':secret,'salt':blob(32),'auth':blob(32),'passwordWrap':WRAP,'recoveryAuth':blob(31)+'A'}
        self.assertProblem(400,lambda:self.app.handle('auth/recovery/complete',body))
        body['recoveryAuth']=blob(32);self.app.handle('auth/recovery/complete',body)
        self.assertProblem(401,lambda:self.app.handle('entries',{},self.session))
        self.assertProblem(400,lambda:self.app.handle('auth/recovery/complete',body))
    def test_expiry_and_account_enumeration(self):
        self.create();a=self.app.handle('auth/salt',{'username':'unknown'})['salt'];b=self.app.handle('auth/salt',{'username':'unknown'})['salt'];self.assertEqual(a,b)
        count=len(self.mail.messages);self.assertEqual(self.app.handle('auth/recovery/start',{'email':'unknown@example.test'})['ok'],True);self.assertEqual(len(self.mail.messages),count)
        self.app.handle('auth/recovery/start',{'email':'anna@example.test'});secret=self.mail.messages[-1][2];self.now[0]+=1801
        self.assertProblem(400,lambda:self.app.handle('auth/recovery/inspect',{'token':secret}))
        self.now[0]+=43200;self.assertProblem(401,lambda:self.app.handle('entries',{},self.session))
    def test_legacy_migration_atomic_and_erases_live_plaintext(self):
        self.assertProblem(401,lambda:self.app.handle('legacy',{}));self.create()
        self.assertEqual(len(self.app.handle('legacy',{},self.session)['entries']),1)
        wrong={'entries':[{'legacyId':2,'id':str(uuid.uuid4()),'envelope':ENTRY}]}
        self.assertProblem(409,lambda:self.app.handle('legacy/import',wrong,self.session,self.csrf))
        self.assertIn(b'PRIVATE LEGACY SENTINEL',self.legacy.read_bytes())
        good={'entries':[{'legacyId':1,'id':str(uuid.uuid4()),'envelope':ENTRY}]}
        self.assertEqual(self.app.handle('legacy/import',good,self.session,self.csrf)['imported'],1)
        self.assertEqual(self.app.handle('legacy',{},self.session)['entries'],[])
        self.assertNotIn(b'PRIVATE LEGACY SENTINEL',self.legacy.read_bytes())
        self.assertEqual(len(self.app.handle('entries',{},self.session)['entries']),1)
    def test_change_password_revokes_old_sessions(self):
        self.create();body={'oldAuth':blob(32),'salt':blob(32),'auth':blob(32),'passwordWrap':WRAP}
        result,new=self.app.handle('auth/password',body,self.session,self.csrf)
        self.assertProblem(401,lambda:self.app.handle('session',{},self.session));self.assertIn('csrf',self.app.handle('session',{},new))
    def test_http_transport_origin_cookie_headers(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),make_handler(self.app,dev=True));thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        base='http://127.0.0.1:'+str(server.server_port)
        def req(path,origin,data):
            r=urllib.request.Request(base+path,data=json.dumps(data).encode(),headers={'Content-Type':'application/json','Origin':origin},method='POST')
            try:return urllib.request.urlopen(r)
            except urllib.error.HTTPError as e:return e
        try:
            self.assertEqual(req('/api/auth/salt','https://evil.test',{'username':'anna'}).code,403)
            self.create();r=req('/api/auth/login',base,{'username':'anna','auth':blob(32)})
            self.assertEqual(r.code,200);self.assertIn('HttpOnly',r.headers['Set-Cookie']);self.assertIn('SameSite=Strict',r.headers['Set-Cookie']);self.assertNotIn('unsafe-inline',r.headers['Content-Security-Policy'])
            prod=ThreadingHTTPServer(('127.0.0.1',0),make_handler(self.app,dev=False,trusted=()))
            t=threading.Thread(target=prod.serve_forever,daemon=True);t.start()
            try:
                request=urllib.request.Request('http://127.0.0.1:'+str(prod.server_port)+'/api/bootstrap',headers={'Host':PUBLIC_HOST})
                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self,*args):return None
                try:urllib.request.build_opener(NoRedirect).open(request)
                except urllib.error.HTTPError as response:
                    self.assertEqual(response.code,308);self.assertEqual(response.headers['Location'],ORIGIN+'/')
            finally:prod.shutdown();prod.server_close()
        finally:server.shutdown();server.server_close()

if __name__=='__main__':unittest.main()
