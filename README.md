# HTB Write-ups

<p align="left">
  <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img alt="htb" src="https://www.hackthebox.eu/badge/image/391067"></a>
  </br>
  <img align="float:right" alt="size" src="https://img.shields.io/github/repo-size/x00tex/hackTheBox">
</p>

**New retired box:** [Horizontall](Boxes/linux/Retired/horizontall/README.md)


## <img width="20" hight="20" src="assets/android.png"> Android

|Box|Difficulty|Writeup|Foothold|Privesc|
|---|----------|-------|--------|-------|
|<a href="https://app.hackthebox.eu/machines/Explore"><img width="25" hight="25" alt="explore" src="assets/explore.webp"></a>|<span style="color:green">Easy</span>|[Explore](Boxes/android/Retired/explore/README.md)|[ES Explorer CVE-2019–6447](Boxes/android/Retired/explore/README.md#es-file-explorer-open-port-vulnerability)|[`adb` Root](Boxes/android/Retired/explore/README.md#adb-root)|


## :penguin:*nix

|Box|Difficulty|Writeup|Foothold|Privesc|
|---|----------|-------|--------|-------|
|<a href="https://app.hackthebox.eu/machines/Armageddon"><img width="25" hight="25" alt="armageddon" src="assets/armageddon.webp"></a>|<span style="color:green">Easy</span>|[armageddon](Boxes/linux/Retired/armageddon/README.md)|[Drupal property injection: Drupalgeddon 2](Boxes/linux/Retired/armageddon/README.md#drupal-property-injection-drupalgeddon-2)|[`snap install` with sudo](Boxes/linux/Retired/armageddon/README.md#snap-install-with-sudo)|
|<a href="https://app.hackthebox.eu/machines/BountyHunter"><img width="25" hight="25" alt="bountyHunter" src="assets/bountyHunter.webp"></a>|<span style="color:green">Easy</span>|[BountyHunter](Boxes/linux/Retired/bountyHunter/README.md)|[xxe](Boxes/linux/Retired/bountyHunter/README.md#xxe)|[python script logic](Boxes/linux/Retired/bountyHunter/README.md#python-script-logic)|
|<a href="https://app.hackthebox.eu/machines/Cap"><img width="25" hight="25" alt="cap" src="assets/cap.webp"></a>|<span style="color:green">Easy</span>|[Cap](Boxes/linux/Retired/cap/README.md)|[Parameter Manipulation](Boxes/linux/Retired/cap/README.md#parameter-manipulation) And [PCAP file analysis](Boxes/linux/Retired/cap/README.md#pcap-file-analysis)|[python with `setuid` capability](Boxes/linux/Retired/cap/README.md#python-with-setuid-capability)|
|<a href="https://app.hackthebox.eu/machines/CrossFitTwo"><img width="25" hight="25" alt="CrossFitTwo" src="assets/crossFitTwo.webp"></a>|<span style="color:red">INSANE :warning:</span>|[CrossFitTwo](Boxes/linux/Retired/crossFitTwo/README.md)|[Websocket](Boxes/linux/Retired/crossFitTwo/README.md#websocket) And [SQL injection: blind/Union](Boxes/linux/Retired/crossFitTwo/README.md#sql-injection) And [DNS Hijacking](Boxes/linux/Retired/crossFitTwo/README.md#dns-hijacking) And [CSRF](Boxes/linux/Retired/crossFitTwo/README.md#csrf)|[Node module hijack](Boxes/linux/Retired/crossFitTwo/README.md#node-module-hijack) And [Yubikey](Boxes/linux/Retired/crossFitTwo/README.md#yubikey)|
|<a href="https://app.hackthebox.eu/machines/Developer"><img width="25" hight="25" alt="developer" src="assets/developer.webp"></a>|<span style="color:red">Hard</span>|[Developer](Boxes/linux/Retired/developer/README.md)|[Reverse tab-nabbing](Boxes/linux/Retired/developer/README.md#reverse-tab-nabbing) And [Django Deserialization](Boxes/linux/Retired/developer/README.md#django-deserialization)|[Postgresql Enumeration](Boxes/linux/Retired/developer/README.md#postgresql-enumeration)|
|<a href="https://app.hackthebox.eu/machines/Dynstr"><img width="25" hight="25" alt="Dynstr" src="assets/dynstr.webp"></a>|<span style="color:orange">Medium</span>|[Dynstr](Boxes/linux/Retired/dynstr/README.md)|[ISC BIND DNSserver](Boxes/linux/Retired/dynstr/README.md#isc-bind-dnsserver) And [Command Injection in Bind API](Boxes/linux/Retired/dynstr/README.md#command-injection-in-dyn-api)|[DNS pointer record(PTR)](Boxes/linux/Retired/dynstr/README.md#dns-pointer-recordptr) And [Wildcard in `cp` Command](Boxes/linux/Retired/dynstr/README.md#wildcard-in-cp-command)|
|<a href="https://app.hackthebox.eu/machines/Forge"><img width="25" hight="25" alt="forge" src="assets/forge.webp"></a>|<span style="color:orange">Medium</span>|[Forge](Boxes/linux/Retired/forge/README.md)|[SSRF](Boxes/linux/Retired/forge/README.md#ssrf)|[Python pdb Module](Boxes/linux/Retired/forge/README.md#python-pdb-module)|
|<a href="https://app.hackthebox.eu/machines/Horizontall"><img width="25" hight="25" alt="horizontall" src="assets/horizontall.webp"></a>|<span style="color:green">Easy</span>|[Horizontall](Boxes/linux/Retired/horizontall/README.md)|[Improper Access Control](Boxes/linux/Retired/horizontall/README.md#improper-access-control) And [Command Injection](Boxes/linux/Retired/horizontall/README.md#command-injection)|[Laravel <8.4.2 RCE](Boxes/linux/Retired/horizontall/README.md#laravel-842-debug-mode-with-ignition-252-rce)|
|<a href="https://app.hackthebox.eu/machines/Knife"><img width="25" hight="25" alt="knife" src="assets/knife.webp"></a>|<span style="color:green">Easy</span>|[Knife](Boxes/linux/Retired/knife/README.md)|[backdoored php Version](Boxes/linux/Retired/knife/README.md#backdoored-php-version)|[`knife` with sudo](Boxes/linux/Retired/knife/README.md#knife-command-with-sudo)|
|<a href="https://app.hackthebox.eu/machines/Monitors"><img width="25" hight="25" alt="monitors" src="assets/monitors.webp"></a>|<span style="color:red">Hard</span>|[Monitors](Boxes/linux/Retired/monitors/README.md)|[wp-plugin "Spritz" LFI](Boxes/linux/Retired/monitors/README.md#wp-plugin-spritz-lfi) And ["cacti" SQLi Stacked Queries to RCE](Boxes/linux/Retired/monitors/README.md#cacti-sqli-stacked-queries-to-rce)|[Socat Portforwarding](Boxes/linux/Retired/monitors/README.md#socat-portforwarding) And ["ofbiz" Deserialization RCE](Boxes/linux/Retired/monitors/README.md#ofbiz-deserialization-rce) And [Container with `SYS_MODULE` Capability](Boxes/linux/Retired/monitors/README.md#container-with-sys_module-capability)|
|<a href="https://app.hackthebox.eu/machines/Ophiuchi"><img width="25" hight="25" alt="ophiuchi" src="assets/ophiuchi.webp"></a>|<span style="color:orange">Medium</span>|[ophiuchi](Boxes/linux/Retired/ophiuchi/README.md)|[SnakeYAML Deserilization](Boxes/linux/Retired/ophiuchi/README.md#snakeyaml-deserilization)|[wasm reversing](Boxes/linux/Retired/ophiuchi/README.md#wasm-reversing)|
|<a href="https://app.hackthebox.eu/machines/Pikaboo"><img width="25" hight="25" alt="pikaboo" src="assets/pikaboo.webp"></a>|<span style="color:red">Hard</span>|[Pikaboo](Boxes/linux/Retired/pikaboo/README.md)|[URL parser logic in nginx server](Boxes/linux/Retired/pikaboo/README.md#url-parser-logicdirectory-traversal-in-nginx) And [lfi to RCE via ftp log](Boxes/linux/Retired/pikaboo/README.md#lfi)|[Perl jam: Command Injection](Boxes/linux/Retired/pikaboo/README.md#perl-command-injection)|
|<a href="https://app.hackthebox.eu/machines/Pit"><img width="25" hight="25" alt="pit" src="assets/pit.webp"></a>|<span style="color:orange">Medium</span>|[Pit](Boxes/linux/Retired/pit/README.md)|[SNMP Enumeration](Boxes/linux/Retired/pit/README.md#snmp-enumeration) And [Login Form Bruteforce with hydra](Boxes/linux/Retired/pit/README.md#login-form-bruteforce-with-hydra) And [SeedDMS RCE](Boxes/linux/Retired/pit/README.md#seeddms-rce)|[Access control list(ACL)](Boxes/linux/Retired/pit/README.md#access-control-listacl) And [SNMP Extend Command](Boxes/linux/Retired/pit/README.md#snmp-extend-command)|
|<a href="https://app.hackthebox.eu/machines/Previse"><img width="25" hight="25" alt="previse" src="assets/previse.webp"></a>|<span style="color:green">Easy</span>|[Previse](Boxes/linux/Retired/previse/README.md)|[Blind Command Injection](Boxes/linux/Retired/previse/README.md#blind-command-injection)|[Absolute Path Injection](Boxes/linux/Retired/previse/README.md#absolute-path-injection)|
|<a href="https://app.hackthebox.eu/machines/Ready"><img width="25" hight="25" alt="ready" src="assets/ready.webp"></a>|<span style="color:orange">Medium</span>|[Ready](Boxes/linux/Retired/ready/README.md)|[gitlab <11.4.8 SSRF via IPv6](Boxes/linux/Retired/ready/README.md#gitlab-1148-ssrf-via-ipv6) And [redis server RCE](Boxes/linux/Retired/ready/README.md#new-line-injection-to-exploit-internal-redis-server)|[docker container with `--privileged`](Boxes/linux/Retired/ready/README.md#docker-container-with-privileged)|
|<a href="https://app.hackthebox.eu/machines/Schooled"><img width="25" hight="25" alt="schooled" src="assets/schooled.webp"></a>|<span style="color:orange">Medium</span>|[Schooled](Boxes/linux/Retired/schooled/README.md)|[Moodle LMS Enumeration](Boxes/linux/Retired/schooled/README.md#moodle-lms-enumeration) And [XSS in "Moodle"](Boxes/linux/Retired/schooled/README.md#xss-in-moodle) And [Privilege Escalation in "Moodle"](Boxes/linux/Retired/schooled/README.md#privilege-escalation-in-moodle) And [Moodle Admin RCE](Boxes/linux/Retired/schooled/README.md#moodle-admin-rce)|[`pkg` with sudo](Boxes/linux/Retired/schooled/README.md#pkg-with-sudo)|
|<a href="https://app.hackthebox.eu/machines/ScriptKiddie"><img width="25" hight="25" alt="scriptKiddie" src="assets/scriptKiddie.webp"></a>|<span style="color:green">Easy</span>|[scriptKiddie](Boxes/linux/Retired/scriptKiddie/README.md)|[command injection](Boxes/linux/Retired/scriptKiddie/README.md#command-injection)|[`msfconsole` with sudo](Boxes/linux/Retired/scriptKiddie/README.md#msfconsole-with-sudo)|
|<a href="https://app.hackthebox.eu/machines/Seal"><img width="25" hight="25" alt="seal" src="assets/seal.webp"></a>|<span style="color:orange">Medium</span>|[Seal](Boxes/linux/Retired/seal/README.md)|[URL Parser Logic in Apache server](Boxes/linux/Retired/seal/README.md#server-url-parser-logic)|[`ansible-playbook` Command with sudo](Boxes/linux/Retired/seal/README.md#ansible-playbook-command-with-sudo)|
|<a href="https://app.hackthebox.eu/machines/Sink"><img width="25" hight="25" alt="sink" src="assets/sink.webp"></a>|<span style="color:red">INSANE :warning:</span>|[Sink](Boxes/linux/Retired/sink/README.md)|[http Request Smuggling](Boxes/linux/Retired/sink/README.md#http-request-smuggling)|[AWS secretsmanager](Boxes/linux/Retired/sink/README.md#aws-secretsmanager) And [AWS kms decrypt](Boxes/linux/Retired/sink/README.md#aws-kms-decrypt)|
|<a href="https://app.hackthebox.eu/machines/Spectra"><img width="25" hight="25" alt="spectra" src="assets/spectra.webp"></a>|<span style="color:green">Easy</span>|[Spectra](Boxes/linux/Retired/spectra/README.md)|[wpadmin reverse shell](Boxes/linux/Retired/spectra/README.md#wpadmin-reverse-shell)|[`initctl` with sudo](Boxes/linux/Retired/spectra/README.md#initctl-with-sudo)|
|<a href="https://app.hackthebox.eu/machines/Spider"><img width="25" hight="25" alt="spider" src="assets/spider.webp"></a>|<span style="color:red">HARD</span>|[Spider](Boxes/linux/Retired/spider/README.md)|[SSTI](Boxes/linux/Retired/spider/README.md#ssti) And [SQLi in auth token](Boxes/linux/Retired/spider/README.md#sqli-in-auth-token) And [Blind restricted SSTI](Boxes/linux/Retired/spider/README.md#blind-restricted-ssti)|[XXE to inject payload in auth token](Boxes/linux/Retired/spider/README.md#xxe-to-inject-payload-in-auth-token)|
|<a href="https://app.hackthebox.eu/machines/Tentacle"><img width="25" hight="25" alt="tentacle" src="assets/tentacle.webp"></a>|<span style="color:red">Hard</span>|[Tentacle](Boxes/linux/Retired/tentacle/README.md)|[DNS Enumeration](Boxes/linux/Retired/tentacle/README.md#dns-enumeration) And [squid proxy](Boxes/linux/Retired/tentacle/README.md#squid-proxy) And [ffuf with multi-proxy](Boxes/linux/Retired/tentacle/README.md#ffuf-with-multi-proxy) And [OpenSMTPD RCE](Boxes/linux/Retired/tentacle/README.md#opensmtpd-rce)|[ssh with kerberos token](Boxes/linux/Retired/tentacle/README.md#ssh-with-kerberos-token) And [k5login](Boxes/linux/Retired/tentacle/README.md#k5login) And [kadmin](Boxes/linux/Retired/tentacle/README.md#kadmin)|
|<a href="https://app.hackthebox.eu/machines/TheNotebook"><img width="25" hight="25" alt="theNotebook" src="assets/theNotebook.webp"></a>|<span style="color:orange">Medium</span>|[theNotebook](Boxes/linux/Retired/theNotebook/README.md)|[jwt bypass](Boxes/linux/Retired/theNotebook/README.md#jwt-bypass)|[Breaking Docker via runC](Boxes/linux/Retired/theNotebook/README.md#breaking-docker-via-runc)|
|<a href="https://app.hackthebox.eu/machines/Unobtainium"><img width="25" hight="25" alt="unobtainium" src="assets/unobtainium.webp"></a>|<span style="color:red">Hard</span>|[Unobtainium](Boxes/linux/Retired/unobtainium/README.md)|[reversing Electron application deb package](Boxes/linux/Retired/unobtainium/README.md#reversing-electron-application-deb-package) And [Prototype Pollution](Boxes/linux/Retired/unobtainium/README.md#prototype-pollution) And [Command injection](Boxes/linux/Retired/unobtainium/README.md#command-injection)|[Kubernetes](Boxes/linux/Retired/unobtainium/README.md#kubernetes) And [Kubectl](Boxes/linux/Retired/unobtainium/README.md#kubectl) And [kubernetes admin](Boxes/linux/Retired/unobtainium/README.md#kubernetes-with-admin-token)|
|<a href="https://app.hackthebox.eu/machines/Writer"><img width="25" hight="25" alt="writer" src="assets/writer.webp"></a>|<span style="color:orange">Medium</span>|[Writer](Boxes/linux/Retired/writer/README.md)|[UNION sqli TO file read](Boxes/linux/Retired/writer/README.md#union-sqli-to-file-read) And [RCE using SSRF with smb](Boxes/linux/Retired/writer/README.md#rce-using-ssrf-with-smb) And [Unintended: Command Injection via filename](Boxes/linux/Retired/writer/README.md#command-injection-via-filename)|[postfix automate scripts](Boxes/linux/Retired/writer/README.mdpostfix-automate-scripts) And [Invoke command with apt Configs](Boxes/linux/Retired/writer/README.md#invoke-command-with-apt-configs)|
<!--|<a href="https://app.hackthebox.eu/machines/Static"><img width="25" hight="25" alt="static" src="assets/static.webp"></a>|<span style="color:red">Hard</span>|[Static](Boxes/linux/Retired/static/README.md)|[](Boxes/linux/Retired/static/README.md)|[](Boxes/linux/Retired/static/README.md)|-->


## <img width="25" hight="25" src="assets/win.png"> Windows

|Box|Difficulty|Writeup|Foothold|Privesc|
|---|----------|-------|--------|-------|
|<a href="https://app.hackthebox.eu/machines/Atom"><img width="25" hight="25" alt="atom" src="assets/atom.webp"></a>|<span style="color:orange">Medium</span>|[Atom](Boxes/windows/Retired/atom/README.md)|[Electron-Updater RCE](Boxes/windows/Retired/atom/README.md#electron-updater-rce)|[Kanban credentials Encryption Flaw](Boxes/windows/Retired/atom/README.md#kanban-credentials-encryption-flaw)|
|<a href="https://app.hackthebox.eu/machines/Breadcrumbs"><img width="25" hight="25" alt="breadcrumbs" src="assets/breadcrumbs.webp"></a>|<span style="color:red">Hard</span>|[Breadcrumbs](Boxes/windows/Retired/breadcrumbs/README.md)|[LFI](Boxes/windows/Retired/breadcrumbs/README.md#lfi) And [File upload to RCE](Boxes/windows/Retired/breadcrumbs/README.md#file-upload-to-rce)|[Stickynotes backups](Boxes/windows/Retired/breadcrumbs/README.md#stickynotes-backups) And [sql injection: union](Boxes/windows/Retired/breadcrumbs/README.md#sql-injection)|
|<a href="https://app.hackthebox.eu/machines/Intelligence"><img width="25" hight="25" alt="intelligence" src="assets/intelligence.webp"></a>|<span style="color:orange">Medium</span>|[Intelligence](Boxes/windows/Retired/intelligence/README.md)|[Enumeration](Boxes/windows/Retired/intelligence/README.md#enumeration) And [NTLM Relay Attack](Boxes/windows/Retired/intelligence/README.md#ntlm-relay-attack)|[BloodHound](Boxes/windows/Retired/intelligence/README.md#bloodhound) And [Reading GMSA Password](Boxes/windows/Retired/intelligence/README.md#reading-gmsa-password) And [Silver ticket Attack](Boxes/windows/Retired/intelligence/README.md#silver-ticket-attack)|
|<a href="https://app.hackthebox.eu/machines/Love"><img width="25" hight="25" alt="love" src="assets/love.webp"></a>|<span style="color:green">Easy</span>|[Love](Boxes/windows/Retired/love/README.md)|[File upload to RCE](Boxes/windows/Retired/love/README.md#file-upload-to-rce)|[abusing `AlwaysInstallElevated` policy](Boxes/windows/Retired/love/README.md#abusing-alwaysinstallelevated-policy)|
|<a href="https://app.hackthebox.eu/machines/Proper"><img width="25" hight="25" alt="proper" src="assets/proper.webp"></a>|<span style="color:red">Hard</span>|[Proper](Boxes/windows/Retired/proper/README.md)|[sql injection: blind](Boxes/windows/Retired/proper/README.md#sql-injection) And [RFI via SMB](Boxes/windows/Retired/proper/README.md#smb-connect-via-remote-file-inclusion) And [Race condition with inotify](Boxes/windows/Retired/proper/README.md#race-condition-with-inotify)|[](Boxes/windows/Retired/proper/README.md)|
<!--
|<a href="https://app.hackthebox.eu/machines/Pivotapi"><img width="25" hight="25" alt="pivotapi" src="assets/pivotapi.webp"></a>|<span style="color:red">INSANE :warning:</span>|[Pivotapi](Boxes/windows/Retired/pivotapi/README.md)|[](Boxes/windows/Retired/pivotapi/README.md)|[](Boxes/windows/Retired/pivotapi/README.md)|
-->


<details>
<summary><strong>Old WriteUPs</strong></summary>
<table>
<thead>
<tr>
<th align="left">Box</th>
<th align="center">Difficulty</th>
<th align="right">Writeup</th>
</tr>
</thead>
<tbody>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/Academy"><img width="25" hight="25" alt="academy" src="assets/academy.webp"></a></td>
<td align="center"><span style="color:green">Easy</span></td>
<td align="right"><a href="Boxes/linux/Retired/academy/README.md">Academy</a></td>
</tr>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/Admirer"><img width="25" hight="25" alt="admirer" src="assets/admirer.webp"></a></td>
<td align="center"><span style="color:green">Easy</span></td>
<td align="right"><a href="Boxes/linux/Retired/admirer/README.md">Admirer</a></td>
</tr>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/Blunder"><img width="25" hight="25" alt="blunder" src="assets/blunder.webp"></a></td>
<td align="center"><span style="color:green">Easy</span></td>
<td align="right"><a href="Boxes/linux/Retired/blunder/README.md">Blunder</a></td>
</tr>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/Bucket"><img width="25" hight="25" alt="bucket" src="assets/bucket.webp"></a></td>
<td align="center"><span style="color:orange">Medium</span></td>
<td align="right"><a href="Boxes/linux/Retired/bucket/README.md">Bucket </a></td>
</tr>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/Cache"><img width="25" hight="25" alt="cache" src="assets/cache.webp"></a></td>
<td align="center"><span style="color:orange">Medium</span></td>
<td align="right"><a href="Boxes/linux/Retired/cache/README.md">Cache</a></td>
</tr>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/Compromised"><img width="25" hight="25" alt="compromised" src="assets/compromised.webp"></a></td>
<td align="center"><span style="color:red">Hard</span></td>
<td align="right"><a href="Boxes/linux/Retired/compromised/README.md">Compromised </a></td>
</tr>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/Delivery"><img width="25" hight="25" alt="delivery" src="assets/delivery.webp"></a></td>
<td align="center"><span style="color:green">Easy</span></td>
<td align="right"><a href="Boxes/linux/Retired/delivery/README.md">Delivery</a></td>
</tr>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/Doctor"><img width="25" hight="25" alt="doctor" src="assets/doctor.webp"></a></td>
<td align="center"><span style="color:green">Easy</span></td>
<td align="right"><a href="Boxes/linux/Retired/doctor/README.md">Doctor</a></td>
</tr>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/Feline"><img width="25" hight="25" alt="feline" src="assets/feline.webp"></a></td>
<td align="center"><span style="color:red">Hard</span></td>
<td align="right"><a href="Boxes/linux/Retired/feline/README.md">Feline</a></td>
</tr>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/Jewel"><img width="25" hight="25" alt="jewel" src="assets/jewel.webp"></a></td>
<td align="center"><span style="color:orange">Medium</span></td>
<td align="right"><a href="Boxes/linux/Retired/jewel/README.md">Jewel</a></td>
</tr>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/Laboratory"><img width="25" hight="25" alt="laboratory" src="assets/laboratory.webp"></a></td>
<td align="center"><span style="color:green">Easy</span></td>
<td align="right"><a href="Boxes/linux/Retired/laboratory/README.md">Laboratory</a></td>
</tr>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/Luanne"><img width="25" hight="25" alt="luanne" src="assets/luanne.webp"></a></td>
<td align="center"><span style="color:green">Easy</span></td>
<td align="right"><a href="Boxes/linux/Retired/luanne/README.md">Luanne</a></td>
</tr>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/OpenKeyS"><img width="25" hight="25" alt="openkeyS" src="assets/openkeys.webp"></a></td>
<td align="center"><span style="color:orange">Medium</span></td>
<td align="right"><a href="Boxes/linux/Retired/openkeyS/README.md">OpenKeyS</a></td>
</tr>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/Passage"><img width="25" hight="25" alt="" src="assets/passage.webp"></a></td>
<td align="center"><span style="color:orange">Medium</span></td>
<td align="right"><a href="Boxes/linux/Retired/passage/README.md">passage</a></td>
</tr>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/Tabby"><img width="25" hight="25" alt="tabby" src="assets/tabby.webp"></a></td>
<td align="center"><span style="color:green">Easy</span></td>
<td align="right"><a href="Boxes/linux/Retired/tabby/README.md">Tabby</a></td>
</tr>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/Tenet"><img width="25" hight="25" alt="tenet" src="assets/tenet.webp"></a></td>
<td align="center"><span style="color:orange">Medium</span></td>
<td align="right"><a href="Boxes/linux/Retired/tenet/README.md">Tenet</a></td>
</tr>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/Time"><img width="25" hight="25" alt="time" src="assets/time.webp"></a></td>
<td align="center"><span style="color:orange">Medium</span></td>
<td align="right"><a href="Boxes/linux/Retired/time/README.md">Time</a></td>
</tr>
<tr>
<td align="left"><a href="https://app.hackthebox.eu/machines/Unbalanced"><img width="25" hight="25" alt="unbalanced" src="assets/unbalanced.webp"></a></td>
<td align="center"><span style="color:red">Hard</span></td>
<td align="right"><a href="Boxes/linux/Retired/unbalanced/README.md">Unbalanced</a></td>
</tr>
</tbody>
</table>
</details>


## Disclaimer

* These write up are based on someone's learning processes, who's constantly learning.
* Grammatical/Spelling mistakes.