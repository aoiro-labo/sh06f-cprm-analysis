@echo off
set PATH="..\adb\";%PATH%
:CHECK
echo VpnFakerインストールは、何らかの原因で失敗する可能性、起動ループなどの不具合が起きる危険性があります
echo 念のため/data/local/tmpディレクトリにもpackages.xmlとpackages.listのバックアップを取るようにしてありますが、実行には十分留意の上行ってください
echo /data/local/tmpディレクトリに保存されるpackages.xml、packages.listのバックアップは、ファイル名がpackages_(保存日時)となっています
echo そちらからバックアップを差し替える場合は適宜選択して下さい
echo packages.xmlに不整合が起きると、自動的にpackages.xmlが初期化される可能性が高いため、VpnFakerインストールの前に予めTitanium Backupなどのバックアップアプリを導入し、アプリの設定などをバックアップしておくことを強く推奨します

echo 不具合が起きた場合は、メニューから「VpnFaker導入失敗による起動ループからの復旧」を実行するか、
echo コマンドプロンプトから
echo adb shell
echo $ su
echo # stop zygote
echo # mv /data/system/packages.xml- /data/system/packages.xml
echo # mv /data/system/packages.list- /data/system/packages.list
echo # start zygote
echo 上記のコマンドでバックアップと差し替えてください

echo もし起動ループに陥っても、SHARPロゴのブートアニメが表示されていれば、コマンドプロンプトから
echo adb shell
echo $ su
echo でシェルにログイン出来れば数分経つと起動する場合もあります



echo.
set CHECK=
set /p CHECK=続行する場合は'yes'、終了する場合は'no'と入力してEnterを押してください:
if /i "%CHECK%"=="YES" goto :VPNFAKER
goto :EXITBAT


:VPNFAKER
echo VpnFakerをインストールします
echo 処理途中で自動で再起動し、起動画面で停止しますがそのままお待ちください
pause

adb shell su -c "/data/local/tmp/vpnfaker.sh"
echo.
echo ホーム画面が表示されたら、アプリ一覧にVpnDialogsが追加されているか確認してください
echo コマンドプロンプト画面に
echo su:Operation not permitted
echo というエラーメッセージが表示された場合、先にメニューから２.root有効化を行なってください
echo.
pause

echo.
echo 再起動します
echo しばらくお待ちください
echo.
pause

adb reboot
echo.
echo 正常に起動しましたら、端末のロックを解除してください
echo.
pause

adb shell su -c "id"
echo 画面にuid=0(root) gid=0(root)と表示されていれば永続root化完了です
echo.
echo メニュー画面に戻ります
pause
goto :EXITBAT

:EXITBAT

ping localhost -n 1 > nul
cls
call menu.bat