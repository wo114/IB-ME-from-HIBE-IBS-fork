"""Bounded local fixed issuer with durable pending, atomic publication and pin."""
import os
from pathlib import Path
import stat
import tempfile
from ibme.cli_state import key_issuance_lock
from .codec import MAX_BYTES
from .objects import MasterSecret,_identity
from .params import RingParams


def _sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def _read(path):
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    with os.fdopen(fd,"rb") as f:
        info=os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0<info.st_size<=MAX_BYTES:
            raise ValueError("invalid private state file")
        data=f.read(MAX_BYTES+1)
        if len(data)!=info.st_size:raise ValueError("private state changed while reading")
        return data


class FixedIssuer:
    def __init__(self,path,backend,*,expected_public=None,expected_params=None):
        self.path=Path(path);self.backend=backend
        self.expected_public=expected_public;self.expected_params=expected_params
        self.state=self.path/"master.bin";self.pending=self.path/"master.bin.pending"

    def _directory(self,create=False):
        if self.path.is_symlink():raise ValueError("private state directory is a symlink")
        if create:self.path.mkdir(mode=0o700,parents=True,exist_ok=True)
        if not self.path.is_dir():raise ValueError("private state directory missing")

    def _ready(self):
        if os.path.lexists(self.pending):raise ValueError("pending operation blocks automatic recovery/reissue")

    def _pin(self,pk):
        if self.expected_public is not None and pk.context!=self.expected_public.context:
            raise ValueError("unexpected public context")
        if self.expected_params is not None and pk.params!=self.expected_params:
            raise ValueError("unexpected parameter snapshot")

    def _begin(self):
        fd=os.open(self.pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"wb") as f:
            f.write(b"IBME:SAGELOLI-RING-PENDING:v3\n");f.flush();os.fsync(f.fileno())
        _sync_directory(self.path)

    def _save(self,master):
        raw=master.to_bytes()
        fd,name=tempfile.mkstemp(prefix=".master-",dir=self.path)
        try:
            with os.fdopen(fd,"wb") as f:
                f.write(raw);f.flush();os.fsync(f.fileno())
            os.replace(name,self.state);_sync_directory(self.path)
        finally:
            if os.path.lexists(name):os.unlink(name)

    def _finish(self):
        self.pending.unlink();_sync_directory(self.path)

    def _load(self):
        self._ready();master=self.backend.load_master(_read(self.state))
        self._pin(master.public_key);return master

    def initialize(self,params):
        if not isinstance(params,RingParams):raise TypeError("RingParams required")
        if self.expected_params is not None and params!=self.expected_params:raise ValueError("parameter pin mismatch")
        self._directory(True)
        with key_issuance_lock(self.path):
            self._ready()
            if os.path.lexists(self.state):
                m=self._load()
                if m.public_key.params!=params:raise ValueError("existing state parameter mismatch")
                return m.public_key
            self._begin();pk,master=self.backend.setup(params);self._pin(pk)
            self._save(master);self._finish();return pk

    def public_key(self):
        self._directory()
        with key_issuance_lock(self.path):return self._load().public_key

    def key_extract(self,identity):
        self._directory()
        with key_issuance_lock(self.path):
            master=self._load();p=master.public_key.params;identity=_identity(p,identity)
            if identity in master.states:
                status,key=master.states[identity]
                if status=="issued":return key
                raise ValueError("identity pending/failed; no automatic reissue")
            if len(master.states)>=p.max_users:raise ValueError("identity capacity")
            self._begin();master.states[identity]=("pending",None);self._save(master)
            del master.states[identity]
            try:
                key=self.backend.key_extract(master,identity);self._save(master)
            except BaseException:
                master.states[identity]=("failed",None)
                self._save(master)
                raise
            self._finish();return key
