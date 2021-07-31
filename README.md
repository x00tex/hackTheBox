# HTB Write-ups

<p align="left">
  <a href="https://www.hackthebox.eu/home/users/profile/391067" target="_blank"><img loading="lazy" alt="x00tex" src="https://www.hackthebox.eu/badge/image/391067"></a>
</p>

## :penguin:*nix

|Box|Difficulty|Writeup|Foothold|Privesc|
|---|----------|-------|--------|-------|
|<a href="https://app.hackthebox.eu/machines/Armageddon"><img width="25" hight="25" alt="armageddon" src="assets/armageddon.webp"></a>|<span style="color:green">Easy</span>|[armageddon](Boxes/linux/Retired/armageddon/README.md)|[Drupal: drupalgeddon2](Boxes/linux/Retired/armageddon/README.md#FootholdDrupal_drupalgeddon2)|[`snap install` with sudo](Boxes/linux/Retired/armageddon/README.md#Privescsnap_install_with_sudo)|
|<a href="https://app.hackthebox.eu/machines/Ophiuchi"><img width="25" hight="25" alt="ophiuchi" src="assets/ophiuchi.webp"></a>|<span style="color:orange">Medium</span>|[ophiuchi](Boxes/linux/Retired/ophiuchi/README.md)|[SnakeYAML Deserilization exploit](Boxes/linux/Retired/ophiuchi/README.md#FootholdSnakeYAML_Deserilization_exploit)|[wasm reversing](Boxes/linux/Retired/ophiuchi/README.md#Privescwasm_reversing)|
|<a href="https://app.hackthebox.eu/machines/Ready"><img width="25" hight="25" alt="ready" src="assets/ready.webp"></a>|<span style="color:orange">Medium</span>|[Ready](Boxes/linux/Retired/ready/README.md)|[SSRF in gitlab 11.4.7](Boxes/linux/Retired/ready/README.md#Footholdgitlab_1147_ssrf)|[Docker Privileged Mode](Boxes/linux/Retired/ready/README.md#Privescdocker_privileged_mode)|
|<a href="https://app.hackthebox.eu/machines/ScriptKiddie"><img width="25" hight="25" alt="scriptKiddie" src="assets/scriptKiddie.webp"></a>|<span style="color:green">Easy</span>|[scriptKiddie](Boxes/linux/Retired/scriptKiddie/README.md)|[command_injection in msfvenom](Boxes/linux/Retired/scriptKiddie/README.md#Footholdcommand_injection)|[`msfconsole` with sudo](Boxes/linux/Retired/scriptKiddie/README.md#Privescmsfconsole_with_sudo)|
|<a href="https://app.hackthebox.eu/machines/Spectra"><img width="25" hight="25" alt="spectra" src="assets/spectra.webp"></a>|<span style="color:green">Easy</span>|[Spectra](Boxes/linux/Retired/spectra/README.md)|[wordpress admin rev_shell](Boxes/linux/Retired/spectra/README.md#Footholdwordpress_admin_rev_shell)|[`initctl` with sudo](Boxes/linux/Retired/spectra/README.md#Privescinitctl_with_sudo)|
|<a href="https://app.hackthebox.eu/machines/Tentacle"><img width="25" hight="25" alt="tentacle" src="assets/tentacle.webp"></a>|<span style="color:red">Hard</span>|[Tentacle](Boxes/linux/Retired/tentacle/README.md)|[OpenSMTPD RCE](Boxes/linux/Retired/tentacle/README.md#FootholdOpenSMTPD_RCE)|[Everything kerberos](Boxes/linux/Retired/tentacle/README.md#Privesceverything_kerberos)|
|<a href="https://app.hackthebox.eu/machines/TheNotebook"><img width="25" hight="25" alt="theNotebook" src="assets/theNotebook.webp"></a>|<span style="color:orange">Medium</span>|[theNotebook](Boxes/linux/Retired/theNotebook/README.md)|[jwt bypass](Boxes/linux/Retired/theNotebook/README.md#Footholdjwt_bypass)|[Docker: CVE-2019-5736](Boxes/linux/Retired/theNotebook/README.md#PrivescCVE-2019-5736)|



## <img width="25" hight="25" src="assets/win.png"> Windows

|Box|Difficulty|Writeup|Foothold|Privesc|
|---|----------|-------|--------|-------|
|<a href="https://app.hackthebox.eu/machines/Atom"><img width="25" hight="25" alt="atom" src="assets/atom.webp"></a>|<span style="color:orange">Medium</span>|[Atom](Boxes/windows/Retired/atom/README.md)|[Electron-Updater RCE](Boxes/windows/Retired/atom/README.md#FootholdElectron_Updater-RCE)|[Kanban Decrypt](Boxes/windows/Retired/atom/README.md#PrivescKanban_decrypt)|
|<a href="https://app.hackthebox.eu/machines/Breadcrumbs"><img width="25" hight="25" alt="breadcrumbs" src="assets/breadcrumbs.webp"></a>|<span style="color:red">Hard</span>|[Breadcrumbs](Boxes/windows/Retired/breadcrumbs/README.md)|[File_upload to RCE](Boxes/windows/Retired/breadcrumbs/README.md#FootholdFile_upload_to_RCE)|[Horizontal Privesc](Boxes/windows/Retired/breadcrumbs/README.md#PrivescHorizontal)|



__Old WriteUPs, no screenshots (maybe some of them have some)__

|Box|Difficulty|Writeup|
|---|----------|-------|
|<a href="https://app.hackthebox.eu/machines/Academy"><img width="25" hight="25" alt="academy" src="assets/academy.webp"></a>|<span style="color:green">Easy</span>|[Academy](Boxes/linux/Retired/academy/README.md)|
|<a href="https://app.hackthebox.eu/machines/Admirer"><img width="25" hight="25" alt="admirer" src="assets/admirer.webp"></a>|<span style="color:green">Easy</span>|[Admirer](Boxes/linux/Retired/admirer/README.md)|
|<a href="https://app.hackthebox.eu/machines/Blunder"><img width="25" hight="25" alt="blunder" src="assets/blunder.webp"></a>|<span style="color:green">Easy</span>|[Blunder](Boxes/linux/Retired/blunder/README.md)|
|<a href="https://app.hackthebox.eu/machines/Bucket"><img width="25" hight="25" alt="bucket" src="assets/bucket.webp"></a>|<span style="color:green">Easy</span>|[Bucket ](Boxes/linux/Retired/bucket/README.md)|
|<a href="https://app.hackthebox.eu/machines/Cache"><img width="25" hight="25" alt="cache" src="assets/cache.webp"></a>|<span style="color:orange">Medium</span>|[Cache](Boxes/linux/Retired/cache/README.md)|
|<a href="https://app.hackthebox.eu/machines/Compromised"><img width="25" hight="25" alt="compromised" src="assets/compromised.webp"></a>|<span style="color:red">Hard</span>|[Compromised ](Boxes/linux/Retired/compromised/README.md)|
|<a href="https://app.hackthebox.eu/machines/Delivery"><img width="25" hight="25" alt="delivery" src="assets/delivery.webp"></a>|<span style="color:green">Easy</span>|[Delivery](Boxes/linux/Retired/delivery/README.md)|
|<a href="https://app.hackthebox.eu/machines/Doctor"><img width="25" hight="25" alt="doctor" src="assets/doctor.webp"></a>|<span style="color:green">Easy</span>|[Doctor](Boxes/linux/Retired/doctor/README.md)|
|<a href="https://app.hackthebox.eu/machines/Feline"><img width="25" hight="25" alt="feline" src="assets/feline.webp"></a>|<span style="color:green">Hard</span>|[Feline](Boxes/linux/Retired/feline/README.md)|
|<a href="https://app.hackthebox.eu/machines/Jewel"><img width="25" hight="25" alt="jewel" src="assets/jewel.webp"></a>|<span style="color:orange">Medium</span>|[Jewel](Boxes/linux/Retired/jewel/README.md)|
|<a href="https://app.hackthebox.eu/machines/Laboratory"><img width="25" hight="25" alt="laboratory" src="assets/laboratory.webp"></a>|<span style="color:green">Easy</span>|[Laboratory](Boxes/linux/Retired/laboratory/README.md)|
|<a href="https://app.hackthebox.eu/machines/Luanne"><img width="25" hight="25" alt="luanne" src="assets/luanne.webp"></a>|<span style="color:green">Easy</span>|[Luanne](Boxes/linux/Retired/luanne/README.md)|
|<a href="https://app.hackthebox.eu/machines/OpenKeyS"><img width="25" hight="25" alt="openkeyS" src="assets/openkeys.webp"></a>|<span style="color:orange">Medium</span>|[OpenKeyS](Boxes/linux/Retired/openkeyS/README.md)|
|<a href="https://app.hackthebox.eu/machines/Passage"><img width="25" hight="25" alt="" src="assets/passage.webp"></a>|<span style="color:orange">Medium</span>|[passage](Boxes/linux/Retired/passage/README.md)|
|<a href="https://app.hackthebox.eu/machines/Tabby"><img width="25" hight="25" alt="tabby" src="assets/tabby.webp"></a>|<span style="color:green">Easy</span>|[Tabby](Boxes/linux/Retired/tabby/README.md)|
|<a href="https://app.hackthebox.eu/machines/Time"><img width="25" hight="25" alt="time" src="assets/time.webp"></a>|<span style="color:orange">Medium</span>|[Time](Boxes/linux/Retired/time/README.md)|
|<a href="https://app.hackthebox.eu/machines/Tenet"><img width="25" hight="25" alt="tenet" src="assets/tenet.webp"></a>|<span style="color:orange">Medium</span>|[Tenet](Boxes/linux/Retired/tenet/README.md)|
|<a href="https://app.hackthebox.eu/machines/Unbalanced"><img width="25" hight="25" alt="unbalanced" src="assets/unbalanced.webp"></a>|<span style="color:red">Hard</span>|[Unbalanced](Boxes/linux/Retired/unbalanced/README.md)|

