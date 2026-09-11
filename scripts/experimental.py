"""Isolated experimental feed. No existing catalog is read or modified."""
import base64, concurrent.futures, datetime, hashlib, json, os, pathlib, socket, struct, subprocess, tempfile, time, urllib.parse, urllib.request, uuid
ROOT = pathlib.Path(__file__).resolve().parents[1]

def parse(uri):
    u=urllib.parse.urlsplit(uri); q=dict(urllib.parse.parse_qsl(u.query))
    if u.scheme!='vless' or q.get('type','tcp') not in ('tcp','raw') or q.get('headerType','none')!='none': raise ValueError('unsupported transport')
    if set(q)-{'type','security','encryption','flow','sni','fp','pbk','sid','spx','alpn','headerType','allowInsecure'}: raise ValueError('unsupported parameters')
    if q.get('allowInsecure','0').lower() not in ('0','false',''): raise ValueError('insecure TLS')
    if q.get('security') not in ('tls','reality') or q.get('encryption','none')!='none': raise ValueError('unsupported security')
    secret=str(uuid.UUID(u.username)); host=u.hostname; port=u.port or 443
    if not host: raise ValueError('missing host')
    tls={'serverName':q.get('sni',host),'fingerprint':q.get('fp','chrome')}
    if q.get('alpn'): tls['alpn']=q['alpn'].split(',')
    if q['security']=='reality':
        if not q.get('pbk'): raise ValueError('missing key')
        tls.update(publicKey=q['pbk'],shortId=q.get('sid',''),spiderX=q.get('spx','/'))
    out={'tag':'proxy','protocol':'vless','settings':{'vnext':[{'address':host,'port':port,'users':[{'id':secret,'encryption':'none','flow':q.get('flow','')}]}]},'streamSettings':{'network':'tcp','security':q['security'],('realitySettings' if q['security']=='reality' else 'tlsSettings'):tls}}
    return out

def config(out,port=None):
    c={'log':{'loglevel':'none'},'outbounds':[out,{'tag':'direct','protocol':'freedom'}], 'routing':{'rules':[{'type':'field','network':'tcp,udp','outboundTag':'proxy'}]}}
    if port: c['inbounds']=[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'auth':'noauth','udp':True}}]
    return c

def exact(s,n):
    b=b''
    while len(b)<n:
        a=s.recv(n-len(b))
        if not a: raise OSError('closed')
        b+=a
    return b

def telegram(port):
    # MTProto unencrypted req_pq_multi; validate response nonce, not just TCP.
    with socket.create_connection(('127.0.0.1',port),timeout=8) as s:
        s.settimeout(8);s.sendall(b'\x05\x01\x00');assert exact(s,2)==b'\x05\x00'
        s.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('149.154.167.51')+struct.pack('!H',443))
        h=exact(s,4);assert h[1]==0
        exact(s,4 if h[3]==1 else (16 if h[3]==4 else exact(s,1)[0]));exact(s,2)
        nonce=os.urandom(16);body=bytes.fromhex('f18e7ebe')+nonce
        msg=b'\0'*8+struct.pack('<Q',int(time.time()*2**32)&~3)+struct.pack('<I',len(body))+body
        s.sendall(b'\xef'+bytes([len(msg)//4])+msg)
        n=exact(s,1)[0];n=int.from_bytes(exact(s,3),'little') if n==127 else n
        if n>1024: return False
        response=exact(s,n*4)
        return len(response)>40 and response[20:24]==bytes.fromhex('63241605') and response[24:40]==nonce

def probe(item,binary):
    key,out,sources=item
    with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    result={'id':key,'sources':sources}
    with tempfile.TemporaryDirectory() as d:
        path=pathlib.Path(d)/'config.json';path.write_text(json.dumps(config(out,port)))
        proc=subprocess.Popen([binary,'run','-c',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            time.sleep(.4)
            for label,url in [('telegram_web','https://telegram.org/'),('instagram_web','https://www.instagram.com/')]:
                r=subprocess.run(['curl','--silent','--socks5-hostname',f'127.0.0.1:{port}','--connect-timeout','5','--max-time','10','--max-filesize','2097152','-o',os.devnull,'-w','%{http_code}',url],capture_output=True,text=True)
                result[label]={'http':r.stdout,'ok':r.returncode==0 and r.stdout in ('200','301','302')}
            try:result['telegram_mtproto']=telegram(port)
            except Exception:result['telegram_mtproto']=False
        finally:
            proc.terminate()
            try:proc.wait(timeout=3)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
    return result,out

def main():
    import argparse
    a=argparse.ArgumentParser();a.add_argument('--xray',required=True);a.add_argument('--limit-per-source',type=int,default=25);args=a.parse_args()
    sources=json.loads((ROOT/'experimental/sources.json').read_text());items={};stats=[]
    for source in sources:
        st={'source':source['name'],'url':source['url'],'accepted':0,'unsupported':0}
        try:
            b=urllib.request.urlopen(source['url'],timeout=30).read(8000000).decode('utf-8-sig')
            if '://' not in b:b=base64.b64decode(b+'===').decode()
            for line in b.splitlines():
                if not line.startswith('vless://'):continue
                try:out=parse(line)
                except Exception:st['unsupported']+=1;continue
                key=hashlib.sha256(json.dumps(out,sort_keys=True).encode()).hexdigest()[:12]
                if key in items:items[key][2].append(source['name']);continue
                items[key]=[key,out,[source['name']]];st['accepted']+=1
                if st['accepted']>=args.limit_per_source:break
        except Exception as e:st['error']=type(e).__name__
        stats.append(st)
    print('sources',stats,flush=True)
    results=[];passed=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for result,out in pool.map(lambda item:probe(item,args.xray),items.values()):
            results.append(result)
            if result['telegram_mtproto'] and result['instagram_web']['ok']:
                name='TEST | '+result['sources'][0]+' | '+result['id'];c=config(out);c['remarks']=name;passed.append(c)
            print(result['id'],result['telegram_mtproto'],result['instagram_web'],flush=True)
    report={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'vantage':('GitHub Actions' if os.environ.get('GITHUB_ACTIONS') else 'local Mac; not the user phone'),'scope':'Telegram MTProto req_pq_multi (one DC), Instagram HTTPS. No authenticated media or calls test.','sources':stats,'tested':len(results),'passed':len(passed),'results':results}
    (ROOT/'experimental/report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    if not passed:raise SystemExit('No passing nodes; previous subscriptions preserved')
    (ROOT/'subscription_test_happ.txt').write_text(json.dumps(passed,ensure_ascii=False,indent=2)+'\n')
    from build_clients import connection,yaml_document
    proxies=[connection(c['remarks'],c['outbounds'][0])[1] for c in passed]
    clash={'mode':'rule','proxies':proxies,'proxy-groups':[{'name':'TEST','type':'select','proxies':[p['name'] for p in proxies]}],'rules':['MATCH,TEST']}
    (ROOT/'subscription_test_karing.txt').write_text(yaml_document(clash))
if __name__=='__main__':main()
