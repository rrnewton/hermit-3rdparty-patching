#!/usr/bin/env python3
"""Require the real installed patching cohort and explicit e9 executables.
This is an artifact guard, never a guest or an availability-success probe.
"""
import hashlib,os,stat,subprocess,sys
from pathlib import Path

def stable_identity(info):
    # Reads may update atime; retain every other original stat identity field.
    return (info.st_mode, info.st_ino, info.st_dev, info.st_nlink,
            info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def held(name):
    value=os.environ.get(name,'')
    path=Path(value)
    if not value or not path.is_absolute() or path.resolve(strict=True)!=path:
        raise ValueError(name+': explicit canonical absolute artifact required')
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not before.st_mode&0o111 or before.st_size==0:
            raise ValueError(name+': artifact is not an executable regular file')
        with os.fdopen(os.dup(fd),'rb') as source:
            if source.read(4)!=b'\x7fELF':raise ValueError(name+': artifact is not ELF')
            source.seek(0);digest=hashlib.file_digest(source,'sha256').hexdigest()
        if stable_identity(os.fstat(fd))!=stable_identity(before) or stable_identity(path.stat())!=stable_identity(before):raise ValueError(name+': artifact changed while held')
        return path,fd,before,digest
    except BaseException:
        os.close(fd);raise

def main():
    items=[]
    try:
        for name in ('HERMIT_E9TOOL','HERMIT_E9PATCH_BACKEND'):items.append(held(name))
        root=Path(os.environ['HERMIT_PATCHING_ROOT']);core=Path(os.environ['HERMIT_CORE_SOURCE']);cohort=Path(os.environ['HERMIT_PATCHING_COHORT'])
        for path in (root,core,cohort):
            if not path.is_absolute() or path.resolve(strict=True)!=path:raise ValueError('explicit canonical source/cohort required')
        # The exact production verifier owns schema2/source/engine+shim closure.
        # e9 itself remains preprocessing followed by the core ptrace runtime.
        result=subprocess.run([sys.executable,'-B',str(root/'hermit-patching-cli/native/verify.py'),'--core-source',str(core),'--cohort',str(cohort)],check=False)
        for path,fd,before,digest in items:
            with os.fdopen(os.dup(fd),'rb') as source:
                source.seek(0);after=hashlib.file_digest(source,'sha256').hexdigest()
            if stable_identity(os.fstat(fd))!=stable_identity(before) or stable_identity(path.stat())!=stable_identity(before) or after!=digest:raise ValueError('explicit e9 artifact changed during cohort verification: '+str(path))
        return result.returncode
    finally:
        for _,fd,_,_ in items:os.close(fd)

if __name__=='__main__':
    try:raise SystemExit(main())
    except (OSError,ValueError,KeyError) as error:
        print('require-ci-products.py: '+str(error),file=sys.stderr);raise SystemExit(2)
