import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch,Mock
from ops.updater import REQUIRED,Updater,activate,parse_tree,safe_path,read_commit

class SourceTests(unittest.TestCase):
    def test_rejects_escape_runtime_files_and_links(self):
        for path in ['../vault.sqlite3','/etc/passwd','x/../../etc/passwd','.git/config','data/vault.sqlite3','release.json','x\\server.py','name\nfile']:
            with self.subTest(path=path),self.assertRaises(ValueError):safe_path(path)
        tree=b'\0'.join(b'100644 blob '+b'a'*40+b'\t'+name.encode() for name in REQUIRED)+b'\0'
        self.assertEqual(len(parse_tree(tree)),len(REQUIRED))
        with self.assertRaises(ValueError):parse_tree(tree+b'120000 blob '+b'b'*40+b'\tlinked.py\0')
        with self.assertRaises(ValueError):parse_tree(tree+b'160000 commit '+b'b'*40+b'\tdependency\0')
        with self.assertRaises(ValueError):parse_tree(b'100644 blob '+b'a'*40+b'\tserver.py\0')

@unittest.skipUnless(os.name=='posix','Activation uses Linux symlinks and systemd paths')
class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.old=self.root/'old';self.new=self.root/'new';self.old.mkdir();self.new.mkdir()
        for path,sha in [(self.old,'a'*40),(self.new,'b'*40)]: (path/'release.json').write_text(json.dumps({'commit':sha}))
        self.current=self.root/'current';self.current.symlink_to(self.old,target_is_directory=True)
        self.data=self.root/'private-data';self.data.mkdir();(self.data/'vault.sqlite3').write_bytes(b'ENCRYPTED USER DATA - never replaced')
        self.config={'repository':'https://github.com/example/little-pause.git','branch':'main','state':str(self.root/'state'),'current':str(self.current),'releases':str(self.root/'releases'),'data':str(self.data),'app_service':'fixture.service','health_url':'https://example.test/healthz'}
        (self.root/'state/repository.git').mkdir(parents=True)
    def tearDown(self):self.temp.cleanup()
    def test_healthy_release_switches_without_touching_data(self):
        restart=Mock();activate(self.current,self.new,restart,lambda sha:sha=='b'*40)
        self.assertEqual(self.current.resolve(),self.new);restart.assert_called_once()
        self.assertTrue((self.data/'vault.sqlite3').read_bytes().startswith(b'ENCRYPTED USER DATA'))
    def test_failed_health_rolls_back_code_and_preserves_data(self):
        restart=Mock()
        with self.assertRaisesRegex(RuntimeError,'Candidate health'):
            activate(self.current,self.new,restart,lambda sha:sha=='a'*40)
        self.assertEqual(self.current.resolve(),self.old);self.assertEqual(restart.call_count,2)
        self.assertTrue((self.data/'vault.sqlite3').read_bytes().startswith(b'ENCRYPTED USER DATA'))
    def test_failed_tests_never_activate_candidate(self):
        updater=Updater(self.config);updater.fetch=Mock(return_value='b'*40);updater.snapshot=Mock(return_value=[]);updater.archive=Mock();updater.install=Mock()
        with patch('ops.updater.subprocess.run',side_effect=subprocess.CalledProcessError(1,['build'])):
            with self.assertRaises(subprocess.CalledProcessError):updater.run()
        updater.install.assert_not_called();self.assertEqual(read_commit(self.current.resolve()),'a'*40)
        self.assertEqual(json.loads(updater.status_path.read_text())['failed_commit'],'b'*40)
    def test_moving_main_is_not_deployed_after_tests(self):
        updater=Updater(self.config);updater.fetch=Mock(side_effect=['b'*40,'c'*40]);updater.snapshot=Mock(return_value=[]);updater.archive=Mock();updater.install=Mock()
        with patch('ops.updater.subprocess.run'):updater.run()
        updater.install.assert_not_called();self.assertEqual(read_commit(self.current.resolve()),'a'*40)
        self.assertEqual(json.loads(updater.status_path.read_text())['result'],'main-moved-during-checks')

if __name__=='__main__':unittest.main()
