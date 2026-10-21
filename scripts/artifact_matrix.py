"""Verify extracted snapshot CLI variants; never installs packages or builds binaries."""
from pathlib import Path
import argparse, base64, collections, concurrent.futures, copy, gzip, hashlib, json, os, re, shutil, struct, subprocess, tarfile, time, tomllib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from artifact_inventory import sha, verify_checksum_inventory
from candidate_checks import check_cli_result

def main():
    if not __debug__:
        raise RuntimeError("validation requires Python assertions enabled")
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--dist',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--version',required=True)
    parser.add_argument('--qemu',type=Path,required=True)
    parser.add_argument('--legacy-archive',type=Path,required=True)
    options=parser.parse_args()
    OUT=options.out.resolve(); ROOT=options.source.resolve(); DIST=options.dist.resolve()
    assert not OUT.exists(),'use a new output directory; never overwrite evidence'
    OUT.mkdir(parents=True,mode=0o700)
    (OUT/'released-v0.12.0').mkdir(mode=0o700)
    INPUTS=tomllib.loads((ROOT/'scripts/candidate-inputs.toml').read_text())
    assert sha(options.legacy_archive)==INPUTS['legacy']['sha256']
    shutil.copyfile(options.legacy_archive,OUT/'released-v0.12.0/kensa_0.12.0_linux_amd64.tar.gz')
    WARNING='Legacy v1 signature is valid; rollback results are not authenticated.'
    QEMU=options.qemu.resolve()
    assert sha(QEMU)==INPUTS['qemu']['binary_sha256']
    ENV={k:os.environ[k] for k in ('PATH','HOME','USER','LOGNAME','LANG','LC_ALL','TMPDIR') if k in os.environ}
    ENV['GIT_OPTIONAL_LOCKS']='0'

    def invoke(argv):
        p=subprocess.run([str(x) for x in argv],env=ENV,capture_output=True,text=True,timeout=40)
        return {'argv':[str(x) for x in argv],'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
    def extract(path,dest):
        dest.mkdir(parents=True,exist_ok=False)
        if path.name.endswith('.tar.gz'):
            with tarfile.open(path) as t:t.extractall(dest,filter='data')
        elif path.suffix=='.deb':
            p=invoke(['dpkg-deb','-x',path,dest]);assert p['exit']==0,p
        else:
            # rpm2cpio 4.18.2 returns 1 after emitting a complete payload here.
            # Preserve that failure separately. Require independent RPM digests,
            # gzip CRC/size validation and a successful complete CPIO extraction.
            verified=invoke(['rpm','-Kv',path])
            assert verified['exit']==0 and 'Header SHA256 digest: OK' in verified['stdout'] and 'Payload SHA256 digest: OK' in verified['stdout'],verified
            data=path.read_bytes();assert data[:4]==bytes.fromhex('edabeedb')
            def header_end(offset):
                assert data[offset:offset+4]==bytes.fromhex('8eade801')
                count,size=struct.unpack('>II',data[offset+8:offset+16])
                end=offset+16+16*count+size
                assert end<=len(data)
                return end
            end=header_end(96);start=(end+7)//8*8
            payload_start=header_end(start)
            assert data[payload_start:payload_start+2]==b'\x1f\x8b'
            content=gzip.decompress(data[payload_start:])
            assert content.startswith(b'070701') and b'TRAILER!!!' in content[-1024:]
            payload=dest.parent/(path.name+'.cpio');payload.write_bytes(content)
            (dest.parent/(path.name+'.rpm-digests.json')).write_text(json.dumps(verified,indent=2)+'\n')
            with payload.open('rb') as source:
                r=subprocess.run(['cpio','-idmu','--quiet','--no-absolute-filenames','--no-preserve-owner'],cwd=dest,stdin=source,capture_output=True,text=True)
            assert r.returncode==0,(r.returncode,r.stderr)
        return dest/('usr/bin/kensa' if path.suffix in ('.deb','.rpm') else 'kensa')

    ARTIFACTS=sorted([p for p in DIST.iterdir() if p.is_file() and (p.name.endswith('.tar.gz') or p.suffix in ('.deb','.rpm','.sha256'))])
    assert len(ARTIFACTS)==11, [p.name for p in ARTIFACTS]
    checks,checksums,sbom=verify_checksum_inventory(DIST,options.version)
    document=json.loads(sbom.read_text())
    assert document['bomFormat']=='CycloneDX' and document['components'] and sbom.name in checksums

    FIX=OUT/'matrix-fixtures';FIX.mkdir()
    base_doc=json.loads((ROOT/'internal/evidence/testdata/numeric-vectors.json').read_text())
    v1vector=next(v for v in base_doc['vectors'] if v['name']=='v1/integer')
    v2vector=json.loads((ROOT/'internal/evidence/testdata/v2-vectors.json').read_text())['vectors'][0]
    base={'v1':copy.deepcopy(v1vector['envelope']),'v2':copy.deepcopy(v2vector['envelope'])}
    # The legacy limitation control is a copy with excluded rows; the released
    # signature and all signed data remain unchanged. No original file is edited.
    base['v1']['rollback_results']=copy.deepcopy(base['v2']['rollback_results'])
    def no_float(value):
        assert not isinstance(value,float),'fixture preparation must not round numbers'
        if isinstance(value,dict):
            for entry in value.values():no_float(entry)
        if isinstance(value,list):
            for entry in value:no_float(entry)
    for env in base.values():no_float(env)
    public=Ed25519PublicKey.from_public_bytes(base64.b64decode(v1vector['public_key']))
    pem=public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    keyid=base['v1']['signing_key_id'];assert keyid==base['v2']['signing_key_id']
    trust=FIX/'trust';trust.mkdir();(trust/(keyid+'.pub')).write_bytes(pem)
    missing=FIX/'empty-trust';missing.mkdir()
    bad_pem=FIX/'bad-pem';bad_pem.mkdir();(bad_pem/(keyid+'.pub')).write_text('not a PEM key\n')
    wrong=FIX/'wrong-key';wrong.mkdir();other=Ed25519PrivateKey.from_private_bytes(bytes([7])*32).public_key()
    (wrong/(keyid+'.pub')).write_bytes(other.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo))
    alias='0'*64;(trust/(alias+'.pub')).write_bytes(pem)
    seed=Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    CASES=[]
    for version in ('v1','v2'):
        changes=[('valid',{},True,''),('key-id-warning',{'signing_key_id':alias},True,''),
                 ('bad-signature',{'signature':base64.b64encode(bytes([1])*64).decode()},False,'signature does not match'),
                 ('short-signature',{'signature':base64.b64encode(bytes(63)).decode()},False,'signature wrong length'),
                 ('unsigned',{'signature':None},False,'signature wrong length'),
                 ('unsigned-errored',{'signature':None,'decision':'errored'},False,'unsigned errored'),
                 ('unsigned-recovered',{'signature':None,'decision':'recovered'},False,'unsigned recovered'),
                 ('empty-key-id',{'signing_key_id':''},False,'empty signing_key_id'),
                 ('malformed-key-id',{'signing_key_id':'../outside'},False,'unexpected format'),
                 ('empty-version',{'schema_version':''},False,'missing schema_version'),
                 ('unknown-version',{'schema_version':'v99'},False,'unknown schema_version'),
                 ('swapped-version',{'schema_version':'v2' if version=='v1' else 'v1'},False,'signature does not match'),
                 ('severity-edit',{'severity':'edited'},False,'signature does not match')]
        canonical=base64.b64decode(v1vector['canonical'] if version=='v1' else v2vector['canonical'])
        tag=b'kensa-evidence-envelope-'+(b'v2' if version=='v1' else b'v1')+b'\0'
        changes.append(('wrong-domain',{'signature':base64.b64encode(seed.sign(tag+canonical)).decode()},False,'signature does not match'))
        for name,updates,valid,reason in changes:
            env=copy.deepcopy(base[version]);env.update(updates)
            CASES.append((version,name,env,trust,valid,reason))
        for name,directory,reason in [('missing-key',missing,'not found'),('malformed-pem',bad_pem,'PEM'),('wrong-key',wrong,'signature does not match')]:
            CASES.append((version,name,base[version],directory,False,reason))
        edits={'StepIndex':9,'Mechanism':'edited','Success':False,'Detail':'edited','PartialRestore':True,'Source':'edited','ExecutedAt':'2026-10-20T00:00:00.123456789Z'}
        for field,value in edits.items():
            env=copy.deepcopy(base[version]);assert env['rollback_results'][0][field]!=value,(field,value)
            env['rollback_results'][0][field]=value
            CASES.append((version,'rollback-'+field,env,trust,version=='v1','signature does not match' if version=='v2' else ''))
        for name in ('add','remove','reorder'):
            env=copy.deepcopy(base[version]);rows=env['rollback_results'];assert len(rows)>1
            if name=='add':rows.append(copy.deepcopy(rows[0]))
            if name=='remove':rows.pop()
            if name=='reorder':rows.reverse()
            CASES.append((version,'rollback-'+name,env,trust,version=='v1','signature does not match' if version=='v2' else ''))
    for version,name,env,directory,valid,reason in CASES:
        (FIX/(version+'-'+name+'.json')).write_text(json.dumps(env,separators=(',',':'))+'\n')
    malformed=FIX/'malformed.json';malformed.write_text('{')
    trailing=FIX/'trailing.json';trailing.write_text('{} {}')
    INPUT_HASHES={str(p.relative_to(FIX)):sha(p) for p in FIX.rglob('*') if p.is_file()}
    (OUT/'matrix-input-hashes.json').write_text(json.dumps(INPUT_HASHES,indent=2)+'\n')

    BINARIES=[];package_info=[]
    for path in ARTIFACTS:
        if path.suffix=='.sha256':continue
        dest=OUT/'extracted'/path.name
        binary=extract(path,dest)
        info={'artifact':str(path),'artifact_sha256':sha(path),'extracted':str(dest),'contains_cli':binary.is_file()}
        if binary.is_file():
            info.update(binary=str(binary),binary_sha256=sha(binary),architecture='arm64' if '_arm64' in path.name else 'amd64')
            BINARIES.append(info)
        else:assert path.name.startswith('kensa-rules_'),path
        package_info.append(info)
    assert len(BINARIES)==8
    for arch in ('amd64','arm64'):
        assert len({x['binary_sha256'] for x in BINARIES if x['architecture']==arch})==1
    (OUT/'artifact-manifest.json').write_text(json.dumps({'artifacts':package_info,'checksum_file_sha256':sha(checks),'sbom_sha256':sha(sbom),'sbom_components':len(document['components'])},indent=2)+'\n')

    def matrix(info):
        prefix=[str(QEMU)] if info['architecture']=='arm64' else []
        binary=info['binary'];label=Path(info['artifact']).name
        version_run=invoke(prefix+[binary,'version']);assert version_run['exit']==0 and version_run['stdout'].split()[1]==options.version,version_run
        records=[]
        for version,name,env,directory,valid,reason in CASES:
            path=FIX/(version+'-'+name+'.json')
            for legacy in (False,True):
                accepted=valid and (version=='v2' or legacy)
                for fmt in ('text','json'):
                    for quiet in (False,True):
                        args=prefix+[binary,'verify',str(path),'--trust-dir',str(directory),'--format',fmt]
                        if legacy:args.append('--accept-legacy-v1')
                        if quiet:args.append('--quiet')
                        repeats=[]
                        for _ in range(2):
                            r=invoke(args);r.update(version=version,case=name,format=fmt,quiet=quiet,legacy=legacy)
                            check_cli_result(r, valid, accepted, version, fmt, quiet, name, reason)
                            repeats.append(r);records.append(r)
                        assert repeats[0]==repeats[1],(label,name,'nonrepeatable')
        usage=[('malformed',[str(malformed)],'malformed JSON'),('trailing',[str(trailing)],'malformed JSON'),('missing-file',[str(FIX/'absent.json')],'read envelope'),('missing-argument',[],'exactly 1'),('unknown-option',['--bogus'],'unknown flag'),('bad-format',[str(FIX/'v2-valid.json'),'--format','yaml'],'must be')]
        for name,args,reason in usage:
            for legacy in (False,True):
                for quiet in (False,True):
                    command=prefix+[binary,'verify']+args+['--trust-dir',str(trust)]
                    if legacy:command.append('--accept-legacy-v1')
                    if quiet:command.append('--quiet')
                    r=invoke(command);r.update(case=name,quiet=quiet,legacy=legacy)
                    assert r['exit']==2 and WARNING not in r['stderr'] and reason.lower() in r['stderr'].lower(),r
                    records.append(r)
        help_result=invoke(prefix+[binary,'verify','--help'])
        assert help_result['exit']==0 and '--accept-legacy-v1' in help_result['stdout'] and 'rollback results' in help_result['stdout'],help_result
        assert sha(Path(binary))==info['binary_sha256']
        path=OUT/'matrix-output'/ (label+'.json');path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps({'artifact':info,'version':version_run,'help':help_result,'runs':records},indent=2)+'\n')
        print(label,len(records),'checks passed',flush=True)
        return {'artifact':label,'artifact_sha256':info['artifact_sha256'],'binary_sha256':info['binary_sha256'],'runs':len(records),'architecture':info['architecture'],'result':'pass','evidence':str(path),'evidence_sha256':sha(path)}

    start=time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results=list(pool.map(matrix,BINARIES))
    for rel,digest in INPUT_HASHES.items():assert sha(FIX/rel)==digest,rel
    # Observe the actual published old verifier, not only a source-built binary.
    released=OUT/'released-v0.12.0';archive=released/'kensa_0.12.0_linux_amd64.tar.gz'
    old=extract(archive,released/'extracted')
    assert sha(old)==INPUTS['legacy']['binary_sha256']
    legacy=[]
    for version in ('v1','v2'):
        r=invoke([old,'verify',FIX/(version+'-valid.json'),'--trust-dir',trust,'--format','json']);r['fixture_version']=version
        assert r['exit']==(0 if version=='v1' else 1),r
        if version=='v1':assert json.loads(r['stdout'])['valid'] is True,r
        else:assert 'unknown schema_version' in r['stderr'] and '"valid":false' in r['stdout'],r
        legacy.append(r)
    (OUT/'released-v0.12.0/actual-cli-compatibility.json').write_text(json.dumps({'binary_sha256':sha(old),'runs':legacy},indent=2)+'\n')
    summary={'candidate_version':options.version,'artifact_results':results,'candidate_cli_runs':sum(x['runs'] for x in results),'fixture_and_key_files_unchanged':True,'binary_files_unchanged':True,'published_v012_valid_v1_and_rejects_v2':True,'seconds':time.monotonic()-start,'arm64_mode':'qemu-aarch64-static user-mode emulation, not native-host verification','no_installs_hosts_publish_sign_or_git_writes':True}
    summary.update(published_verifier_evidence_sha256=sha(OUT/'released-v0.12.0/actual-cli-compatibility.json'),
                   fixture_hash_inventory_sha256=sha(OUT/'matrix-input-hashes.json'),
                   rpm_digest_records={p.name:sha(p) for p in sorted((OUT/'extracted').glob('*.rpm-digests.json'))})
    (OUT/'artifact-matrix-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary,indent=2),flush=True)

if __name__ == "__main__":
    main()
