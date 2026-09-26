#!/usr/bin/env python3
import html, ipaddress, json, os, secrets, subprocess, tempfile, time, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import yaml

PORT=19090; PROXY_PORT=38443
ROOT=Path('/etc/apn-admin'); STATE=Path('/var/lib/apn-admin/state.json')
MIHOMO=Path('/etc/mihomo/config.yaml'); SUB=ROOT/'subscription.url'
SECRET=(ROOT/'mihomo.secret').read_text().strip(); CSRF=(ROOT/'csrf.secret').read_text().strip()
PRESETS={0,10,20,30,100,150,200,300,400,500}
VPN_NET='10.66.0.0/24'
DIRECT_RULE=['priority','90','from',VPN_NET,'lookup','main']

def run(a, **kw): return subprocess.run(a,text=True,capture_output=True,**kw)
def api(path, method='GET', data=None):
    h={'Authorization':'Bearer '+SECRET}
    b=None if data is None else json.dumps(data).encode()
    if b: h['Content-Type']='application/json'
    with urllib.request.urlopen(urllib.request.Request('http://127.0.0.1:9091'+path,data=b,headers=h,method=method),timeout=8) as r:
        return json.loads(r.read() or b'{}')
def client_ip(h):
    raw=h.headers.get('X-Real-IP') or h.headers.get('X-Forwarded-For','').split(',')[0].strip() or h.client_address[0]
    return str(ipaddress.IPv4Address(raw))
def allow_net(ip):
    net=str(ipaddress.ip_network(ip+'/24',strict=False))
    run(['nft','delete','element','inet','apn_guard','allowed_v4','{',net,'}'])
    r=run(['nft','add','element','inet','apn_guard','allowed_v4','{',net,'timeout','30d','}'])
    if r.returncode: raise RuntimeError(r.stderr)
    s=load_state(); s.setdefault('allowed',{})[net]=int(time.time()+30*86400); save_state(s)
    return net
def load_state():
    try:return json.loads(STATE.read_text())
    except:return {'speed':0,'allowed':{}}
def save_state(s): STATE.write_text(json.dumps(s,ensure_ascii=False,indent=2))
def direct_active():
    rules=run(['ip','rule','show'])
    if rules.returncode: raise RuntimeError(rules.stderr)
    return any(line.strip().startswith('90:') and f'from {VPN_NET} lookup main' in line for line in rules.stdout.splitlines())
def proxy_active():
    rules=run(['ip','rule','show'])
    if rules.returncode: raise RuntimeError(rules.stderr)
    return any(line.strip().startswith('100:') and f'from {VPN_NET} lookup 100' in line for line in rules.stdout.splitlines())
def set_route_mode(mode, persist=True):
    if mode not in ('direct','proxy'): raise ValueError('无效出口模式')
    active=direct_active()
    if mode=='direct' and not active:
        r=run(['ip','rule','add']+DIRECT_RULE)
        if r.returncode: raise RuntimeError(r.stderr)
    elif mode=='proxy':
        routes=run(['ip','route','show','table','100'])
        if routes.returncode or 'default dev tun2socks' not in routes.stdout:
            raise RuntimeError('代理路由未就绪，请检查 tun2socks 和路由表 100')
        if not proxy_active():
            r=run(['ip','rule','add','priority','100','from',VPN_NET,'lookup','100'])
            if r.returncode: raise RuntimeError(r.stderr)
        if active:
            r=run(['ip','rule','del']+DIRECT_RULE)
            if r.returncode: raise RuntimeError(r.stderr)
    if persist:
        s=load_state();s['route_mode']=mode;save_state(s)
def set_speed(mbps):
    if mbps not in PRESETS: raise ValueError('无效限速')
    dev=run(['sh','-c',"ip route show default | awk 'NR==1{print $5}'"]).stdout.strip()
    if not dev: raise RuntimeError('找不到公网网卡')
    run(['tc','qdisc','del','dev',dev,'root'])
    if mbps:
        cmds=[
          ['tc','qdisc','add','dev',dev,'root','handle','1:','htb','default','20'],
          ['tc','class','add','dev',dev,'parent','1:','classid','1:1','htb','rate','1000mbit','ceil','1000mbit'],
          ['tc','class','add','dev',dev,'parent','1:1','classid','1:10','htb','rate',f'{mbps}mbit','ceil',f'{mbps}mbit'],
          ['tc','class','add','dev',dev,'parent','1:1','classid','1:20','htb','rate','1000mbit','ceil','1000mbit'],
          ['tc','filter','add','dev',dev,'protocol','ip','parent','1:','prio','1','u32','match','ip','sport',str(PROXY_PORT),'0xffff','flowid','1:10']]
        for c in cmds:
            r=run(c)
            if r.returncode: raise RuntimeError(r.stderr)
    s=load_state();s['speed']=mbps;save_state(s)
def quota():
    if not SUB.exists(): return '尚未在后台保存订阅链接'
    try:
        req=urllib.request.Request(SUB.read_text().strip(),headers={'User-Agent':'clash.meta'},method='GET')
        with urllib.request.urlopen(req,timeout=15) as r:
            v=r.headers.get('subscription-userinfo',''); r.read(1)
        if not v:return '供应商未提供额度信息'
        d={}
        for x in v.split(';'):
            if '=' in x:
                k,z=x.strip().split('=',1);d[k]=int(z) if z.isdigit() else z
        total=d.get('total',0);used=d.get('upload',0)+d.get('download',0)
        gb=lambda n:f'{n/1073741824:.2f} GB'
        exp=time.strftime('%Y-%m-%d %H:%M',time.localtime(d['expire'])) if d.get('expire') else '未知'
        return f"总量 {gb(total)}｜已用 {gb(used)}｜剩余 {gb(max(0,total-used))}｜到期 {exp}"
    except Exception as e:return '额度查询失败：'+str(e)
def groups():
    try:
        p=api('/proxies').get('proxies',{});out=[]
        for n,v in p.items():
            if v.get('type') in ('Selector','URLTest','Fallback','LoadBalance') and v.get('all'):
                out.append((n,v.get('now',''),v.get('all',[])))
        return out
    except:return []
def exit_ip():
    r=run(['curl','-x',f'http://127.0.0.1:{PROXY_PORT}','-fsS','--max-time','12','https://api.ipify.org'])
    return r.stdout.strip() or '查询失败'
def patch_config(obj):
    for k in ('port','socks-port','mixed-port','allow-lan','bind-address','external-controller','secret'):obj.pop(k,None)
    obj.update({'mixed-port':PROXY_PORT,'allow-lan':True,'bind-address':'0.0.0.0','external-controller':'127.0.0.1:9091','secret':SECRET})
    return obj
def replace_sub(url):
    if not url.startswith('https://'): raise ValueError('订阅必须以 https:// 开头')
    req=urllib.request.Request(url,headers={'User-Agent':'clash.meta'})
    with urllib.request.urlopen(req,timeout=30) as r: raw=r.read(5_000_001)
    if len(raw)>5_000_000: raise ValueError('订阅文件过大')
    obj=yaml.safe_load(raw)
    if not isinstance(obj,dict): raise ValueError('订阅不是 Mihomo YAML 配置')
    data=yaml.safe_dump(patch_config(obj),allow_unicode=True,sort_keys=False).encode()
    old=MIHOMO.read_bytes(); tmp=MIHOMO.with_suffix('.new'); tmp.write_bytes(data)
    td=tempfile.mkdtemp(prefix='mihomo-test-'); Path(td,'config.yaml').write_bytes(data)
    t=run(['/usr/local/bin/mihomo','-t','-d',td])
    if t.returncode: tmp.unlink(missing_ok=True); raise ValueError('新订阅检测失败：'+t.stderr[-300:])
    os.replace(tmp,MIHOMO); r=run(['systemctl','restart','mihomo'])
    if r.returncode or run(['systemctl','is-active','--quiet','mihomo']).returncode:
        MIHOMO.write_bytes(old);run(['systemctl','restart','mihomo']);raise RuntimeError('启动失败，已恢复旧配置')
    SUB.write_text(url);SUB.chmod(0o600)
def page(msg=''):
    gs=groups();s=load_state();opts=''.join(f'<option value="{x}">{x}</option>' for x in sorted(PRESETS))
    mode='服务器直连（13.238.244.226）' if direct_active() else '代理节点'
    cards=''.join('<form method=post action=/switch><input type=hidden name=csrf value="%s"><b>%s</b> 当前：%s<br><select name=node>%s</select><input type=hidden name=group value="%s"><button>切换节点/IP</button></form>'%(CSRF,html.escape(g),html.escape(now),''.join(f'<option>{html.escape(n)}</option>' for n in nodes),html.escape(g)) for g,now,nodes in gs)
    return f'''<!doctype html><meta name=viewport content="width=device-width"><title>APN代理后台</title><style>body{{font:16px system-ui;max-width:760px;margin:auto;padding:18px;background:#f4f6f8}}section,form{{background:white;padding:15px;margin:12px 0;border-radius:12px}}input,select,button{{padding:10px;margin:5px;max-width:95%}}button{{background:#1769e0;color:white;border:0;border-radius:8px}}</style><h1>APN代理后台</h1><p>{html.escape(msg)}</p><section>服务：{html.escape(run(['systemctl','is-active','mihomo']).stdout.strip())}｜VPN出口：{mode}<br>代理出口IP：{html.escape(exit_ip())}<br>订阅：{html.escape(quota())}<br>限速：{'不限速' if not s.get('speed') else str(s['speed'])+' Mbps'}</section><form method=post action=/mode><input type=hidden name=csrf value="{CSRF}"><input type=hidden name=value value=direct><button>切回服务器 IP（VPN直连）</button></form><form method=post action=/allow><input type=hidden name=csrf value="{CSRF}"><button>放行当前手机卡 /24（30天）</button></form><form method=post action=/speed><input type=hidden name=csrf value="{CSRF}"><select name=value>{opts}</select><button>设置限速 Mbps</button></form>{cards}<form method=post action=/subscription><input type=hidden name=csrf value="{CSRF}"><input name=url type=password placeholder="新订阅 https://..." size=55 required><button>检测并替换订阅</button></form>'''
class H(BaseHTTPRequestHandler):
    def log_message(self,*a):pass
    def send(self,body,code=200):
        b=body.encode();self.send_response(code);self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Content-Length',str(len(b)));self.end_headers();self.wfile.write(b)
    def do_GET(self): self.send(page())
    def do_POST(self):
        try:
            n=int(self.headers.get('Content-Length','0'));f=urllib.parse.parse_qs(self.rfile.read(n).decode())
            if f.get('csrf',[''])[0]!=CSRF:raise ValueError('安全校验失败')
            if self.path=='/allow':msg='已放行 '+allow_net(client_ip(self))
            elif self.path=='/speed':set_speed(int(f['value'][0]));msg='限速已更新'
            elif self.path=='/mode':set_route_mode(f['value'][0]);msg='已切回服务器 IP，VPN 重连后检查出口'
            elif self.path=='/switch':
                api('/proxies/'+urllib.parse.quote(f['group'][0],safe=''),'PUT',{'name':f['node'][0]})
                set_route_mode('proxy');msg='节点已切换，VPN 已改走代理'
            elif self.path=='/subscription':replace_sub(f['url'][0].strip());msg='新订阅已生效，旧配置已删除'
            else:raise ValueError('未知操作')
            self.send(page(msg))
        except Exception as e:self.send(page('失败：'+str(e)),400)
if load_state().get('route_mode')=='direct': set_route_mode('direct',persist=False)
ThreadingHTTPServer(('127.0.0.1',PORT),H).serve_forever()
