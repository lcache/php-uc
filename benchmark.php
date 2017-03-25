<?php

// To run from the CLI:
// php -d extension=modules/uc.so benchmark.php uc|apcu|memcache|sqlite

define('OPS', 1024 * 128 * 16);

function bsize($s)
{
	foreach (array('','K','M','G') as $i => $k) {
		if ($s < 1024) break;
		$s/=1024;
	}
	return sprintf("%5.1f %sBytes",$s,$k);
}

function show_fragmentation()
{
    $mem = apcu_sma_info();
    // Fragementation: (freeseg - 1) / total_seg
	$nseg = $freeseg = $fragsize = $freetotal = 0;
	for($i=0; $i<$mem['num_seg']; $i++) {
		$ptr = 0;
		foreach($mem['block_lists'][$i] as $block) {
			if ($block['offset'] != $ptr) {
				++$nseg;
			}
			$ptr = $block['offset'] + $block['size'];
                        /* Only consider blocks <5M for the fragmentation % */
                        if($block['size']<(5*1024*1024)) $fragsize+=$block['size'];
                        $freetotal+=$block['size'];
		}
		$freeseg += count($mem['block_lists'][$i]);
	}
	$frag = sprintf("%.2f%% (%s out of %s in %d fragments)", ($fragsize/$freetotal)*100,bsize($fragsize),bsize($freetotal),$freeseg);
	echo 'Fragmentation: ' . $frag . PHP_EOL;
}

global $argv;
$backend = $argv[1];

switch ($backend) {
    case 'sqlite':
        $db = new PDO('sqlite:/var/tmp/php-uc.sqlite');
        $db->exec('CREATE TABLE uc (address TEXT PRIMARY KEY, data TEXT)');
        $store = $db->prepare('INSERT INTO uc (address, data) VALUES (:address, :data)');
        $fetch = $db->prepare('SELECT data FROM uc WHERE address = :address');
        $delete = $db->prepare('DELETE FROM uc WHERE address = :address');
        break;
    case 'memcache':
        $memcache_obj = memcache_connect('localhost', 11211);
        break;
    case 'apcu':
    case 'uc':
        break;
    default:
        echo 'Backend unknown: ' . $backend . PHP_EOL;
        die();
}

echo 'Using backend: ' . $backend . PHP_EOL;

$bytes = 0;

for ($i = 0; $i < OPS; $i++) {
    if ($i % (OPS / 128) === 0) {
        echo 'Ops: ' . $i . ' / ' . OPS . ' (' . round($i/OPS * 100) . '%)' . PHP_EOL;
    //    show_fragmentation();
    }
    $key = rand(1, 1024);
    $op = rand(0, 10);
    if ($op >= 0 && $op < 4) {
        $size = rand(1, 10000);
        $value = str_repeat('abcdefgh', $size);
        $bytes += $size * 8;
        switch ($backend) {
            case 'uc':
                uc_store('key' . $key, $value);
                break;
            case 'apcu':
                apcu_store('key' . $key, $value);
                break;
        }

        //$memcache_obj->set('key' . $key, $value);
        //$store->bindValue(':address', 'key' . $key);
        //$store->bindValue(':data', $value);
        //$store->execute();
    }
    else if ($op >= 5 && $op < 9) {
        //apcu_fetch('key' . $key);
        //uc_fetch('key' . $key);
        //$memcache_obj->get('key' . $key);
        //$fetch->bindValue(':address', 'key' . $key);
        //$fetch->execute();
    }
    else {
        //apcu_delete('key' . $key);
        //uc_delete('key' . $key);
        //$memcache_obj->delete('key' . $key);
        //$delete->bindValue(':address', 'key' . $key);
        //$delete->execute();
    }
}

//echo 'Wrote ' . round($bytes / 1024 / 1024) . ' MB and performed ' . OPS . ' operations.' . PHP_EOL;

//show_fragmentation();
