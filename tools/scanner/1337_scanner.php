<?php

/*
!1337_SCANNER
@HOST = 127.0.0.1 = Target HOST
@PORT = 80 = Target PORT
@RES = 50000 = Max results
*/
error_reporting(0);
set_time_limit(0);

print "\n+-----------------------[ The Crazy3D Team ]--------------------------+";
print "\n| 1337 SCAN FOR BHR  by The UnKn0wN (Based on KedAns script)          |";
print "\n|          Thanks To KedAns-Dz (Inj3ct0r Team)                        |";
print "\n| Greets to : Dz Offenders Cr3W - Algerian Cyber Army - Inj3ct0r Team |";
print "\n|        www.Dofus-Exploit.com | WwW.IzzI-Hack.com                    |";
print "\n+---------------------------------------------------------------------+\n";

$HOST = gethostbyname($argv[1]);
$PORT = $argv[2];
$MAX = $argv[2];
$allLinks = array();
$allDmns = array();
print "Starting scan (this may take several minutes depending on your internet speed)\n";
function contains($substring, $string) {
$pos = strpos($string, $substring);
if($pos === false) {
return false;
}
else{
return true;
}
}
function check_exploit($cpmxx){
$link ="http://packetstormsecurity.org/search/files/?q=$cpmxx";
$result = @file_get_contents($link);
if (contains("No Results Found",$result))  {
print"\t {PacketSorm => Not Found\n";
}else{
print"\t {PacketSorm => {$link}\n";
}
}
function ask_exploit_db($component){
$exploitdb ="http://www.exploit-db.com/search/?action=search&filter_page=1&filter_description=$component&filter_exploit_text=&filter_author=&filter_platform=0&filter_type=0&filter_lang_id=0&filter_port=&filter_osvdb=&filter_cve=";
$result = @file_get_contents($exploitdb);
if (contains("No results",$result))  {
print"\t {Exploit-DB => Not Found\t\n";
}else{
print"\t {Exploit-DB => {$exploitdb}\n";
}
}
function check_com($source){
preg_match_all('{option,(.*?)/}i',$source,$f);
preg_match_all('{option=(.*?)(&amp;|&|")}i',$source,$f2);
preg_match_all('{/components/(.*?)/}i',$source,$f3);
$arz=array_merge($f2[1],$f[1],$f3[1]);
$coms=array();
if(count($arz)==0){ print "[ Joomla ] ...Nothing Found !\n";}
foreach(array_unique($arz) as $x){
$coms[]=$x;
}
foreach($coms as $comm){
print "    $comm \n"; 
check_exploit($comm);
ask_exploit_db($comm);
}
}
function get_plugins($source){
preg_match_all("#/plugins/(.*?)/#i", $source, $f);
$arz=array_unique($f[1]);
if(count($arz)==0){ print "[ Wordpress ] ...Nothing Found !\n";}
foreach($arz as $plugin){
print "    $plugin \n ";
check_exploit($plugin);
ask_exploit_db($plugin);
}
}
function get_numod($source){
preg_match_all('{?name=(.*?)/}i',$source,$f);
preg_match_all('{?name=(.*?)(&amp;|&|l_op=")}i',$source,$f2);
preg_match_all('{/modules/(.*?)/}i',$source,$f3);
$arz=array_merge($f2[1],$f[1],$f3[1]);
$cpm=array();
if(count($arz)==0){ print "[ Nuke's ] ...Nothing Found !\n";}
foreach(array_unique($arz) as $x){
$cpm[]=$x;
}
foreach($cpm as $nmod){
print "     $nmod \n ";
check_exploit($nmod);
ask_exploit_db($nmod);
}
}
function get_xoomod($source){
preg_match_all('{/modules/(.*?)/}i',$source,$f);
$arz=array_merge($f[1]);
$cpm=array();
if(count($arz)==0){ print "[ Xoops ] ...Nothing Found !\n";}
foreach(array_unique($arz) as $x){
$cpm[]=$x;
}
foreach($cpm as $xmod){
print "     $xmod \n ";
check_exploit($xmod);
ask_exploit_db($xmod);
}
}
function sec($site){
preg_match_all('{http://(.*?)(/index.php)}siU',$site, $sites);
if(contains("www",$sites[0][0])){
return $site=str_replace("index.php","",$sites[0][0]);
}else{
return $site=str_replace("http://","http://www.",str_replace("index.php","",$sites[0][0]));
}}
for($i=0;$i<=$MAX;$i+=10)
{
$x=@file_get_contents('http://www.bing.com/search?q=ip%3A' . $HOST . '+index.php?option=com&first=' . $i);
if ($x)
{
preg_match_all('(<div class="sb_tlst">.*<h3>.*<a href="(.*)".*>(.*)</a>.*</h3>.*</div>)siU', $x, $findlink);
foreach ($findlink[1] as $fl)
$allLinks[]=sec($fl);
if (preg_match('(first=' . $i . '&amp)siU', $x, $linksuiv) == 0) 
{break;	}		   
}
else
break;
}
foreach ($allLinks as $kk => $vv)
{
$allDmns[] = $vv;
}
print("\nSERVER IP   : {$HOST}\n");
print("SITES FOUND : ".count(array_unique($allDmns))."\n\n");
foreach(array_unique($allDmns) as $h3h3){
print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
print("Found site : ".$h3h3."\n");
$source = @file_get_contents($h3h3);
print("\nChecking Joomla Mods ...\n");
check_com($source);
print("\nChecking Wordpress plugins ...\n");
get_plugins($source);
print("\nChecking Nuke's Mods ...\n");
get_numod($source);
print("\nChecking Xoops Mods ...\n");
get_xoomod($source);
}

