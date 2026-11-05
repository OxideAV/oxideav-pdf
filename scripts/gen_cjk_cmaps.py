"""Generate src/reader/data/cjk_cmaps.bin from Adobe's cmap-resources.

Usage: python3 scripts/gen_cjk_cmaps.py <docs/document/pdf/cmap-resources> <out.bin>

The table format is documented in src/reader/cjk.rs. Inputs are the
staged BSD-3-Clause CMap files and cid2code.txt tables (plus the
Adobe-Japan1 JIS X 0208 / 0212 databases).
"""
import os,re,struct,zlib,sys,json
R=sys.argv[1]
COLLS=[('Adobe-Japan1-7','Japan1',['UniJIS-UTF32','UniJIS2004-UTF32','UniJISX0213-UTF32','UniJISX02132004-UTF32']),
       ('Adobe-GB1-6','GB1',['UniGB-UTF32']),
       ('Adobe-CNS1-7','CNS1',['UniCNS-UTF32']),
       ('Adobe-Korea1-2','Korea1',['UniKS-UTF32']),
       ('Adobe-KR-9','KR',['UniAKR-UTF32'])]
tok_re=re.compile(rb'<[0-9A-Fa-f]*>|/[^\s/<>\[\]()]+|\(|\)|[^\s<>/\[\]()]+')
def parse_cmap(path):
    data=open(path,'rb').read()
    data=re.sub(rb'%[^\n\r]*',b'',data)
    toks=tok_re.findall(data)
    cs=[];maps=[];use=None;wmode=0;name=None;ordering=None
    i=0;n=len(toks)
    while i<n:
        t=toks[i]
        if t==b'begincodespacerange':
            i+=1
            while toks[i]!=b'endcodespacerange':
                cs.append((bytes.fromhex(toks[i][1:-1].decode()),bytes.fromhex(toks[i+1][1:-1].decode()))); i+=2
        elif t in (b'begincidrange',):
            i+=1
            while toks[i]!=b'endcidrange':
                lo=bytes.fromhex(toks[i][1:-1].decode()); hi=bytes.fromhex(toks[i+1][1:-1].decode()); cid=int(toks[i+2])
                maps.append(('r',lo,hi,cid)); i+=3
        elif t==b'begincidchar':
            i+=1
            while toks[i]!=b'endcidchar':
                c=bytes.fromhex(toks[i][1:-1].decode()); cid=int(toks[i+1]); maps.append(('r',c,c,cid)); i+=2
        elif t in (b'beginnotdefrange',):
            i+=1
            while toks[i]!=b'endnotdefrange': i+=3
        elif t==b'beginnotdefchar':
            i+=1
            while toks[i]!=b'endnotdefchar': i+=2
        elif t==b'usecmap':
            use=toks[i-1][1:].decode()
        elif t==b'/WMode':
            wmode=int(toks[i+1])
        elif t==b'/Ordering':
            ordering=toks[i+2].decode() if toks[i+1]==b'(' else None
        i+=1
    return dict(cs=cs,maps=maps,use=use,wmode=wmode,ordering=ordering)
def expand(m):
    # component-wise expansion of a cidrange -> {(w,code):cid}; cid offset = linear difference
    out={}
    _,lo,hi,cid=m
    w=len(lo); lov=int.from_bytes(lo,'big')
    def rec(k,prefix):
        if k==w:
            v=int.from_bytes(bytes(prefix),'big'); out[(w,v)]=cid+(v-lov); return
        for b in range(lo[k],hi[k]+1): rec(k+1,prefix+[b])
    rec(0,[])
    return out
paths={}
for d,_,_ in COLLS+[('Adobe-Identity-0','Identity',[])]:
    for f in os.listdir(f'{R}/{d}/CMap'): paths[f]=(d,f'{R}/{d}/CMap/{f}')
parsed={}
def resolved(name):
    if name in parsed: return parsed[name]
    p=parse_cmap(paths[name][1])
    mp={}; cs=[]
    if p['use']:
        base=resolved(p['use']); mp.update(base['map']); cs=list(base['cs'])
    for m in p['maps']: mp.update(expand(m))
    for c in p['cs']:
        if c not in cs: cs.append(c)
    r=dict(map=mp,cs=cs,wmode=p['wmode'],coll=paths[name][0])
    parsed[name]=r; return r
def is_unicode(name): return name.startswith('Uni')
legacy=[f for f in sorted(paths) if not is_unicode(f) and not f.startswith('Adobe-') and not f.startswith('Identity')]

def uv(x):
    o=bytearray()
    while True:
        b=x&0x7f; x>>=7
        if x: o.append(b|0x80)
        else: o.append(b); return bytes(o)
def sv(x): return uv((x<<1) if x>=0 else ((-x)<<1)-1)
def put_runs(runs):
    # runs: list of (a,b,len) sorted by a; deltas: a - prev_end, b - prev_b_end (signed), len
    o=bytearray(uv(len(runs))); pa=0; pb=0
    for a_,b_,l in runs:
        o+=uv(a_-pa)+sv(b_-pb)+uv(l-1); pa=a_+l; pb=b_+l
    return bytes(o)
def mkruns(items, split_lead=False):
    runs=[]
    for a_,b_ in items:
        if runs:
            pa,pb,pl=runs[-1]
            if pa+pl==a_ and pb+pl==b_ and (not split_lead or (a_>>8)==(pa>>8)):
                runs[-1][2]+=1; continue
        runs.append([a_,b_,1])
    return runs
FAMILIES={
 'Japan1':[['RKSJ','83pv-RKSJ','Add-RKSJ','Ext-RKSJ','90pv-RKSJ','90ms-RKSJ','90msp-RKSJ'],['78-RKSJ','78ms-RKSJ'],['EUC'],['78-EUC'],['H','Add','Ext','NWP'],['78']],
 'GB1':[['GB'],['GB-EUC','GBpc-EUC','GBK-EUC','GBKp-EUC','GBK2K'],['GBT'],['GBT-EUC','GBTpc-EUC']],
 'CNS1':[['B5','B5pc','ETen-B5','ETenms-B5','ETHK-B5','HKdla-B5','HKdlb-B5','HKgccs-B5','HKm314-B5','HKm471-B5','HKscs-B5'],['CNS-EUC'],['CNS1'],['CNS2']],
 'Korea1':[['KSC-EUC','KSCpc-EUC','KSCms-UHC','KSCms-UHC-HW'],['KSC'],['KSC-Johab']],
 'KR':[],
}
blob=bytearray(b'OXCJK\x02')
coll_index={}
blob+=uv(len(COLLS))
for k,(d,ordn,cols) in enumerate(COLLS):
    coll_index[d]=k
    rows=[l.rstrip('\n').split('\t') for l in open(f'{R}/{d}/cid2code.txt',encoding='utf-8') if not l.startswith('#')]
    h=rows[0]; idx=[h.index(c) for c in cols]
    ncid=len(rows)-1
    pairs=[]; best={}
    for r in rows[1:]:
        cid=int(r[0])
        for pri,ci in enumerate(idx):
            v=r[ci].strip()
            if v=='*': continue
            hs=[int(p,16) for p in v.split(',') if p.strip() and not p.strip().endswith('v')]
            if pri==0:
                for u in hs: pairs.append((u,cid))
            if cid not in best and hs: best[cid]=min(hs)
        if cid not in best:
            for ci in idx:
                v=r[ci].strip()
                if v=='*': continue
                vs=[int(p.strip()[:-1],16) for p in v.split(',') if p.strip().endswith('v')]
                if vs: best[cid]=min(vs); break
    # Japan1: the JIS X 0208 / 0212 databases name one canonical
    # Unicode per CID where the UTF-32 column lists alternatives.
    if ordn=='Japan1':
        for jf in ('jisx0208-jp90.txt','jisx0212-jp90.txt'):
            jl=[l.rstrip('\n').split('\t') for l in open(f'{R}/{d}/{jf}',encoding='utf-8') if not l.startswith('#')]
            jh=jl[0]; ui=jh.index('Unicode'); ci=jh.index('Adobe-Japan1-6')
            for r in jl[1:]:
                u=r[ui].strip(); c=r[ci].strip().strip('[]')
                if u.startswith('U+') and c.isdigit(): best[int(c)]=int(u[2:],16)
    # A CID no Unicode column reaches (proportional / half-width /
    # vertical variants only legacy CMaps select) takes the character
    # its code denotes in a sibling CMap of the same encoding.
    fams=FAMILIES[ordn]
    for fam in fams:
        cols_i=[h.index(c) for c in fam if c in h]
        code2cids={}
        for r in rows[1:]:
            cid=int(r[0])
            for ci in cols_i:
                v=r[ci].strip()
                if v=='*': continue
                for p in v.split(','):
                    p=p.strip()
                    if not p or p.endswith('v'): continue
                    code2cids.setdefault(int(p,16),[]).append(cid)
        for code,cids in code2cids.items():
            us=[best[c] for c in cids if c in best]
            if not us: continue
            u=min(set(us),key=lambda x:(-us.count(x),x))
            for c in cids:
                if c not in best: best[c]=u
    runs=mkruns(sorted(best.items()))
    uc={}
    for u,c in sorted(pairs):
        if u not in uc: uc[u]=c
    uruns=mkruns(sorted(uc.items()))
    nb=ordn.encode()
    blob+=uv(len(nb))+nb+uv(ncid)+put_runs(runs)+put_runs(uruns)
    print(ordn,ncid,len(best),'runs',len(runs),'uruns',len(uruns),file=sys.stderr)
blob+=uv(len(legacy))
tot=0
names=list(legacy)
for name in legacy:
    r=resolved(name)
    p=parse_cmap(paths[name][1])
    parent=p['use'] if p['use'] in legacy else None
    nb=name.encode()
    blob+=uv(len(nb))+nb+uv(coll_index[r['coll']])+uv(r['wmode'])
    if parent:
        base=resolved(parent)['map']
        own={k:v for k,v in r['map'].items() if base.get(k)!=v}
        removed=[k for k in base if k not in r['map']]
        assert not removed, name
        blob+=uv(names.index(parent)+1)
        mp=own
        cs=[c for c in r['cs'] if c not in resolved(parent)['cs']]
    else:
        blob+=uv(0); mp=r['map']; cs=r['cs']
    blob+=uv(len(cs))
    for lo,hi in cs: blob+=uv(len(lo))+lo+hi
    for w in (1,2,3,4):
        items=sorted((c,cid) for (ww,c),cid in mp.items() if ww==w)
        runs=mkruns(items, split_lead=True)
        blob+=put_runs(runs); tot+=len(runs)
print('legacy',len(legacy),'runs',tot,'raw',len(blob),file=sys.stderr)
z=zlib.compress(bytes(blob),9)
print('zlib',len(z),file=sys.stderr)
open(sys.argv[2],'wb').write(z)
