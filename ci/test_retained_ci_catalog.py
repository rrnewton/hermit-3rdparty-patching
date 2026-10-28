#!/usr/bin/env python3
"""Actual catalog producer binding guards; no runtime/backend qualification."""
import hashlib,importlib.util,json,os,shutil,sys,tempfile,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('catalog',Path(__file__).with_name('generate-retained-ci.py'))
catalog=importlib.util.module_from_spec(spec);spec.loader.exec_module(catalog)
class CatalogBindings(unittest.TestCase):
    def test_distinct_entries_bind_actual_elf_metadata_and_refuse_changed_or_duplicate_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();selected={}
            for name in ['ptrace','sabre','e9patch']:
                path=root/name;shutil.copyfile(Path(sys.executable).resolve(),path);path.chmod(0o700);selected[name]=path
            rows=[]
            for name,path in selected.items():
                stat=path.stat();rows.append(dict(backend=name,producer_backend=name,executable=str(path),sha256=hashlib.sha256(path.read_bytes()).hexdigest(),binary_build_sha='a'*40,dev=stat.st_dev,ino=stat.st_ino,size=stat.st_size,mtime=stat.st_mtime_ns//10**9,mtime_nsec=stat.st_mtime_ns%10**9,ctime=stat.st_ctime_ns//10**9,ctime_nsec=stat.st_ctime_ns%10**9))
            document=root/'bindings.json'
            def write(values):document.write_text(json.dumps(dict(schema=1,bindings=values)))
            write(rows);catalog.bindings(document,selected)
            for bad in [rows[:-1],rows+[rows[0]], [{**row,'sha256':'0'*64} if row['backend']=='sabre' else row for row in rows]]:
                write(bad)
                with self.assertRaises(ValueError):catalog.bindings(document,selected)
            write(rows);selected['sabre'].write_bytes(b'changed')
            with self.assertRaises(ValueError):catalog.bindings(document,selected)
    def test_pinned_inputs_use_only_the_actual_paired_mounts_and_distinct_outputs(self):
        core=Path('/host/core');project=Path('/host/project');out=Path('/out/core');other=Path('/out/project')
        self.assertEqual(catalog.mounted(out/'target/validate/helper',core,project,out,other),'/src/target/validate/helper')
        self.assertEqual(catalog.mounted(other/'target/debug/hermit-sabre',core,project,out,other),'/project/target/debug/hermit-sabre')
        self.assertEqual(catalog.mounted(core/'Cargo.toml',core,project,out,other),'/src/Cargo.toml')
        with self.assertRaisesRegex(ValueError,'outside the paired'):
            catalog.mounted(Path('/unmounted/helper'),core,project,out,other)
if __name__=='__main__':unittest.main()
