"""Check packaged numeric behavior, binary metadata and corpus contents."""
import argparse,base64,copy,hashlib,importlib.util,io,json,os,stat,subprocess,tarfile,tomllib
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from candidate_checks import check_numeric_signature, check_sudoers

def main():
    if not __debug__:
        raise RuntimeError("validation requires Python assertions enabled")
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--matrix-out',type=Path,required=True);p.add_argument('--qemu',type=Path,required=True);p.add_argument('--version',required=True);a=p.parse_args()
    source=a.source.resolve();out=a.matrix_out.resolve();dest=out/'additional-controls';assert not dest.exists();dest.mkdir(mode=0o700)
    env={k:os.environ[k] for k in ('PATH','HOME','USER','LOGNAME','LANG','LC_ALL','TMPDIR') if k in os.environ}
    def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
    def call(argv):
     r=subprocess.run([str(x) for x in argv],env=env,capture_output=True,text=True,timeout=60);return {'argv':[str(x) for x in argv],'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
    spec=importlib.util.spec_from_file_location('lossless_verifier',source/'scripts/verify-envelope-vectors.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
    doc=v.loads_lossless((source/'internal/evidence/testdata/numeric-vectors.json').read_text())
    manifest=json.loads((out/'artifact-manifest.json').read_text());records=[];python_checks=[];metadata=[]
    INPUTS=tomllib.loads((source/'scripts/candidate-inputs.toml').read_text())
    legacy=out/'released-v0.12.0/extracted/kensa';assert sha(legacy)==INPUTS['legacy']['binary_sha256']
    trust=out/'matrix-fixtures/trust';warning='Legacy v1 signature is valid; rollback results are not authenticated.'
    # Independent exact-contract positives and numeric-tamper negatives, both versions.
    for entry in doc['vectors']:
     check_numeric_signature(entry, v)
     python_checks.append({'vector':entry['name'],'original':'valid','numeric_edit':'rejected'})
    # Actual packaged CLI controls retain released v1 normalization, not a new form.
    for info in manifest['artifacts']:
     if not info.get('contains_cli'):continue
     binary=Path(info['binary']);before=sha(binary);prefix=[a.qemu] if info['architecture']=='arm64' else []
     for entry in doc['vectors']:
      version,name=entry['name'].split('/',1);original=v.dumps_lossless(entry['envelope']);cases=[('original',original)]
      if name in ('integer','exact-large-integer'):
       number='1000' if name=='integer' else '9007199254740992';needle='"number":'+number;assert needle in original
       cases.extend([('decimal',original.replace(needle,needle+'.0')),('exponent',original.replace(needle,'"number":'+('1e3' if name=='integer' else '9.007199254740992e15')))])
       if name=='exact-large-integer':cases.append(('rounded-neighbor',original.replace(needle,'"number":9007199254740993')))
      for spelling,text in cases:
       valid=(version=='v2' and spelling=='original') or (version=='v1' and name in ('integer','float-tiny','float-large','float-exponent','exact-large-integer'))
       fixture=dest/(entry['name'].replace('/','-')+'-'+spelling+'.json');fixture.write_text(text);before_fixture=sha(fixture)
       args=['verify',fixture,'--trust-dir',trust,'--format','json'];run=call(prefix+[binary]+args+(['--accept-legacy-v1'] if version=='v1' else []));body=json.loads(run['stdout'])
       assert run['exit']==(0 if valid else 1) and body['valid']==valid and body['accepted']==valid,run
       assert body['rollback_results_authenticated']==(valid and version=='v2'),run
       assert (warning in run['stderr'])==(valid and version=='v1'),run
       if not valid:assert 'signature does not match' in body.get('error',''),run
       if version=='v1':
        old=call([legacy]+args);assert old['exit']==(0 if valid else 1) and json.loads(old['stdout'])['valid']==valid,old
        records.append({'artifact':'published-v0.12.0','vector':entry['name'],'spelling':spelling,'result':old})
       assert sha(fixture)==before_fixture
       records.append({'artifact':Path(info['artifact']).name,'vector':entry['name'],'spelling':spelling,'result':run})
     assert sha(binary)==before
    # Version and ELF/static checks cover all four packaged binaries, not kensa-fuzz.
    for info in manifest['artifacts']:
     root=Path(info['extracted']);archive=Path(info['artifact']);entry={'artifact':archive.name}
     if info.get('contains_cli'):
      prefix=[a.qemu] if info['architecture']=='arm64' else []
      for name in ('kensa','kensa-validate','kensa-keygen','kensa-systemd-helper'):
       path=root/name if archive.name.endswith('.tar.gz') else root/('usr/libexec/' if name=='kensa-systemd-helper' else 'usr/bin/')/name
       assert path.is_file() and stat.S_IMODE(path.stat().st_mode)==0o755,path
       run=call(prefix+[path,'--version']);assert run['exit']==0 and run['stdout'].split()[1]==a.version,run
       elf=call(['readelf','-l',path]);assert elf['exit']==0 and 'INTERP' not in elf['stdout'],elf
       header=call(['readelf','-h',path]);assert header['exit']==0
       assert ('AArch64' if info['architecture']=='arm64' else 'X86-64') in header['stdout'],header
       metadata.append({'artifact':archive.name,'binary':name,'version':run,'program_headers':elf,'elf_header':header})
      if archive.suffix=='.deb':
       raw=subprocess.check_output(['dpkg-deb','--fsys-tarfile',str(archive)],env=env)
       with tarfile.open(fileobj=io.BytesIO(raw)) as t:m=t.getmember('./etc/sudoers.d/kensa-systemd-helper');check_sudoers(m.mode, m.uid, m.gid, True)
       raw=subprocess.check_output(['dpkg-deb','--ctrl-tarfile',str(archive)],env=env)
       with tarfile.open(fileobj=io.BytesIO(raw)) as t:assert '/etc/sudoers.d/kensa-systemd-helper' in t.extractfile('./conffiles').read().decode().splitlines()
       entry['sudoers']='0440 uid/gid 0; conffile'
      elif archive.suffix=='.rpm':
       run=call(['rpm','-qp','--queryformat','[%{FILENAMES}\t%{FILEMODES}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILEFLAGS}\n]',archive]);assert run['exit']==0,run
       row=next(s.split('\t') for s in run['stdout'].splitlines() if s.startswith('/etc/sudoers.d/kensa-systemd-helper\t'))
       check_sudoers(int(row[1]), row[2], row[3], bool(int(row[4])&1))
       entry['sudoers_query']=run
     # Actual rule payloads must match the committed candidate corpus.
     corpus=root/'rules' if archive.name.endswith('_with-rules.tar.gz') else root/'usr/share/kensa/rules' if archive.name.startswith('kensa-rules_') else None
     if corpus:
      expected={str(p.relative_to(source/'rules')):sha(p) for p in (source/'rules').rglob('*.yml')};expected['README.md']=sha(source/'rules/README.md')
      actual={str(p.relative_to(corpus)):sha(p) for p in corpus.rglob('*') if p.is_file()};assert actual==expected,archive
      assert all(stat.S_IMODE(p.stat().st_mode)==(0o755 if p.is_dir() else 0o644) for p in corpus.rglob('*')),archive
      entry['corpus_files']=len(actual);entry['corpus_matches_candidate']=True
     metadata.append(entry)
    (dest/'results.json').write_text(json.dumps({'status':'passed','numeric_cli':records,'independent_numeric':python_checks,'artifact_metadata':metadata,'lossless_numeric_inputs':True,'no_installs_hosts_or_publication':True},indent=2)+'\n')
    print(json.dumps({'numeric_cli_runs':len(records),'independent_numeric_vectors':len(python_checks),'metadata_records':len(metadata),'all_pass':True}))

if __name__ == "__main__":
    main()
