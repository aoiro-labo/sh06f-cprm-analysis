SHARP_android_rooting_tools ver.7.0 2014/06/22

rootツール群をまとめ、バッチとシェルスクリプトで半自動化しています。
一応動作確認はしていますが、あくまで人柱版です。自己責任でお願いします。
何か問題がありましたら、スレへの書き込みをお願いします。
"At your own risk"

※スレでの報告ありがとうございました。VpnFakerのインストールですが、調べた所タイミングによってなかなか上手くいかないケースが他機種でも確認されているようです。もしかしたら、vpnfaker.sh内のスクリプトを手動で一行ずつ実行するほうが良いかもしれません。また、失敗しても何度か実行すると上手くいくケースもある模様です。
※SH-06Eについては、system領域ににライトプロテクトが施されているため、本ツールでは仮rootまでしか取得できません。SH-06E rootスレにおいてツールが公開されていますのでそちらを利用してください。
※CVE-2013-6282 put_user_exploitによって通常のユーザー権限からのroot権限昇格が可能になっています。利用には十分注意してください。
※fi01氏の尽力によって、未登録端末でもアドレスを自動検索することでroot取得及びアンロックが可能になった模様です。よって、以下の対応機種以外のSHARP端末でも動作する可能性があります。

－－－－－－－対応機種－－－－－－－－
SH-02E　   build 02.00.03
SH-02E　   build 02.00.04
SH-04E　   build 01.00.02
SH-04E　   build 01.00.03
SH-04E　   build 01.00.04
SH-05E　   build 01.00.05
SH-05E　   build 01.00.06
SH-07E     build 01.00.03
SHL21 　   build 01.00.09
SHL21 　   build 01.01.02
SHL21 　   build 01.01.03
SH-09D　   build 02.00.03
SBM203SH   build S0018
SBM203SH   build S0022
SBM203SH   build S0024
(SH-08E     build ????????)
(SH-10D     build ????????)

－－－－－－－操作方法－－－－－－－－
start.batを実行してください。
root取得操作は1→2→3の順番です。
バッチファイルは大まかに以下の5つの処理を行います。

メニュー
１．仮root奪取：仮rootを取得します。その後suバイナリ、busyboxバイナリを/system/xbinディレクトリに設置し、SuperSUアプリをインストールします。/system下を変更するため文鎮化の危険があります。
２．root有効化＆nand,miyabi unlock：miyabi,mmc_protectをアンロックし、suコマンドを有効にします。なお、端末のみでもアンロックが可能です。その場合は端末エミュレータなどで/data/local/tmp/onBootを実行してください。　※Android 4.1では、先にmiyabiをアンロックしないとsuコマンドが無効化されます。
３．VpnFakerインストール：VpnFakerをインストールし、永続rootを取得します。
４．unroot：root権限を放棄し、各種アプリとファイルを削除します。
５．VpnFaker導入失敗による起動ループからの復旧：VpnFaker導入失敗時に起動ループが発生した場合の復旧処理を実行します　※android標準のリカバリーモードではありません

ファイル一覧
/
readme.txt
start.bat

/files/adb
adb.exe
AdbWinApi.dll
AdbWinUdbApi.dll

/files/bat
doroot.bat
getroot.bat
menu.bat
recovery.bat
unroot.bat
vpnfaker.bat

/files/bin
busybox
fix_cve_2013_6282
get_essential_address
install_backdoor
run_autoexec
run_root_shell
su
unlock_lsm_miyabi
unlock_mmc_protect

/files/etc
device.db
SuperSU.apk
VpnFakerV2.tar.gz

/files/sh
autoexec.sh
getroot.sh
onBoot
recovery.sh
unroot.sh
vpnfaker.sh


ファイル解説
・run_root_shell：仮rootを取得します。
・install_backdoor：メモリにパッチを当て、アンロックの準備を行います。
・unlock_lsm_miyabi：miyabi LSMをアンロックします。
・unlock_mmc_protect：mmc_protect(nandロック)をアンロックします。
・VpnFaker：偽装ターミナルアプリです。端末起動時にonBootスクリプト(nand,miyabiアンロック)をsystem権限(uid=1000)で実行します。
・get_essential_address：root取得及びアンロックに必要な端末のアドレスを自動で検索し、DB
に登録します。

あとがき
android_run_root_shell,backdoor_mmap_tools,VpnFakerの作者様である@fi01_is01氏及び@hiikezoe氏には多大なる感謝を申し上げます。
このツールでは、上記のファイルの一部、または全部を使用させていただきました。
バッチファイルの一部は SH-01D_102SH_root-tools_ICS を参考にさせていただきました。
改めて、制作に携わった方々には感謝申し上げます。


Special Thanks
@fi01_is01
@hiikezoe
@goroh_kun
SH-02E,SH-09D,SH-06E rootスレ住民
(敬称略)


ファイルソース
https://github.com/fi01/backdoor_mmap_tools
https://github.com/android-rooting-tools/android_run_root_shell
https://github.com/android-rooting-tools/android_get_essential_address
http://www1.axfc.net/uploader/so/2977572.zip

build (linux)
git clone --recursive https://github.com/android-rooting-tools/android_run_root_shell
cd android_run_root_shell
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk

git clone --recursive https://github.com/android-rooting-tools/android_get_essential_address
cd android_get_essential_address
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk

git clone --recursive https://github.com/fi01/backdoor_mmap_tools
cd backdoor_mmap_tools
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk

更新履歴
ver 1.0　SH-02E_SH-04E_SH-05E_root_tools　としてツール公開
ver 2.0　VpnFakerインストール時の不具合を修正
ver 3.0　SHL21を対応機種に追加、バイナリ更新
ver 4.0　SHARP_android_rooting_tools　に名称変更　対応機種にSH-09D、SBM203SHを追加
ver 5.0　対応機種にSH-07Eを追加　一部スクリプトの修正　（不具合により削除）
ver 6.0　バイナリ更新　アドレス自動検索により対応機種以外も動作可能に？　バッチファイル及びスクリプト修正 adbを最新verに更新
ver 7.0　アップローダの有効期限切れに伴い、ファイル各種更新、再アップロード

2014/06/22
-------------------------------------