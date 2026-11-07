"""Isolated local UI fixture. Never deploy or use this mail sink in production."""
import json
from pathlib import Path
import sqlite3
from http.server import ThreadingHTTPServer
from server import App,make_handler

root=Path(__file__).resolve().parent/'.test-state'
root.mkdir(exist_ok=True)
class Sink:
    ready=True
    def send(self,to,kind,secret):(root/'mail.json').write_text(json.dumps({'to':to,'kind':kind,'token':secret}))
legacy=root/'legacy.sqlite3'
if not legacy.exists():
    db=sqlite3.connect(legacy)
    db.execute('CREATE TABLE entries(id INTEGER PRIMARY KEY,created TEXT,previous TEXT,next TEXT,note TEXT)')
    db.execute("INSERT INTO entries VALUES(1,'2026-11-06T19:00:00Z','A busy afternoon','A walk in the garden','A small moment worth keeping.')")
    db.commit();db.close()
app=App(root/'data','fixture-invitation',legacy,Sink())
print('Isolated UI fixture: http://127.0.0.1:18095/#invite=fixture-invitation',flush=True)
ThreadingHTTPServer(('127.0.0.1',18095),make_handler(app,dev=True)).serve_forever()
