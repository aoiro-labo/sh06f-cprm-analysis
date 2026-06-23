# ルートA：Windows 7 32bit VM（VMware Player）で SD-MobileImpact を動かす手順

最終更新: 2026-06-19 ／ 構成: **Windows 7 32bit ＋ VMware Workstation Player**

> 狙い：Win11の壁（86000001＝mirssom.dll の use-after-unload クラッシュ／32bitドライバ非ロード／
> Win10+のCPRM撤去）を全部回避。**配布終了済みの正規CPRMモジュール一式は本PCに既存**なので、
> それを移植して使う。ワンセグ復号・再生（→キャプチャ）と、RE（動的解析）の土台になる。

## ⚠️ 対応OSについて（重要・2026-06-19 追記）
- **Panasonic公式：SD-MobileImpactは Windows 7 / 8 非対応（対応予定なし）**。
  ＝本来の対応OSは **Windows XP / Vista（2006年世代）**。
- よって **最も確実な土台は Windows XP SP3 32bit（次点 Vista 32bit）**。
  BN-SDCMP3＋audsub3.sys もXP世代設計で相性が最良。
- **Win7 32bit でも試す価値はある**（SD-Jukebox系をWin7/10で動かした例あり。Win11固有の
  mirssomクラッシュはWin7では出ない可能性）。ただし**動作保証なし**。ダメならXP/Vistaへ。
- 移植バンドル（フォルダ/レジストリ/ドライバ）は **32bit Windowsなら XP/Vista/7 共通**で使える。
  - XPで使う場合のみ注意：**`setup.bat` の自己昇格部分（PowerShell/RunAs）はXPで動かない**。
    XPは既定で管理者なので、その場合は昇格行を消した簡易版を使う（必要なら別途用意可）。

## 用意するもの
- VMware Workstation Player（個人利用無償）
- Windows 7 32bit のインストールメディア（ISO）＋プロダクトキー
- 移植バンドル：`doc/_migration_kit/SDMI_Win7_bundle.zip`（43MB、下記4点入り）
  - `SD-MobileImpact\`（本体）／`SDApf\`（★CPRM＋ワンセグ復号スタック）／`SD-PML\`／`SDApp\`
  - `Panasonic_Win7_32bit.reg`（Win7 32bit用に書換済みレジストリ）

## ★かんたん版（自動配置 setup.bat）

`SDMI_Win7_bundle.zip` の中に **`setup.bat`** を同梱済み。VM内でこれ1つ実行すれば
**配置・レジストリ取込・VC++ランタイム・audsubドライバ導入まで自動**でやる。

1. VMware Player に Win7 32bit を用意（下記「1. VM作成」）。
2. `SDMI_Win7_bundle.zip` をゲストへ転送し、**任意の場所に解凍**（例: デスクトップ）。
3. 解凍フォルダ内の **`setup.bat` を右クリック →「管理者として実行」**
   （管理者でなければ自動で昇格を促す）。画面の指示でVC++とドライバを入れる。
4. 完了後、**BN-SDCMP3をUSBパススルー**（下記「4.」）→ `SD-MobileImpact.exe` を管理者起動。

setup.bat がやること（手動でやる場合は下記「手順」を参照）:
`SD-MobileImpact`→`C:\Program Files\Panasonic\` / `SDApf`+`SD-PML`+`SDApp`→`C:\Program Files\Common Files\Panasonic\`
/ `reg import` / `vcredist_x86.exe` / `instaudsub.exe`。

---

## 手順（手動で行う場合）

### 1. VM作成
1. VMware Player で新規VM → Win7 32bit をISOからインストール。
2. メモリ2GB以上、ディスク40GB程度。インストール後 **VMware Tools を導入**
   （ドラッグ&ドロップ／共有フォルダが使えるようになる）。
3. ネットは繋がなくてよい（むしろオフライン推奨。Panasonicサーバは死んでいる）。

### 2. ファイル移植（ホスト→ゲスト）
1. `SDMI_Win7_bundle.zip` をゲストへ転送（ドラッグ&ドロップ or 共有フォルダ）。
2. ゲストで解凍し、以下へ配置（**32bit Win7なので "(x86)" は付かない**）:
   - `SD-MobileImpact\` → `C:\Program Files\Panasonic\SD-MobileImpact\`
   - `SDApf\`  → `C:\Program Files\Common Files\Panasonic\SDApf\`
   - `SD-PML\` → `C:\Program Files\Common Files\Panasonic\SD-PML\`
   - `SDApp\`  → `C:\Program Files\Common Files\Panasonic\SDApp\`
   - ※ `SD-MobileImpact\mirssom.dll.bak` は不要なら削除可（害は無い）。

### 3. レジストリ・ランタイム・ドライバ
1. `Panasonic_Win7_32bit.reg` をダブルクリックで取込み（管理者）。
2. `C:\Program Files\Panasonic\SD-MobileImpact\vcredist_x86.exe` を実行（VC++2005ランタイム）。
3. `instaudsub.exe` を**右クリック→管理者として実行**（リーダー用 audsub3.sys 導入）。
   - Win7が未署名ドライバを警告したら「このドライバーソフトウェアをインストールします」。
   - 起動時に弾かれる場合は、起動時F8→「ドライバー署名の強制を無効にする」。
   - （補足：`SDCprm.dll`はSPTI直叩きなので、最悪audsubが入らなくても通る可能性はある）

### 4. リーダーをVMへUSBパススルー
1. BN-SDCMP3（microSDスロットに**元microSD**挿入のまま）をホストPCに接続。
2. VMware Player メニュー → **Player ▸ Removable Devices ▸ (BN-SDCM... を探す) ▸ Connect**
   （"Connect (Disconnect from Host)"）。
3. ゲストWin7がUSBマスストレージとして認識（標準USBSTORドライバ）。
   ドライブとしてmicroSDが見えればOK（空のSDスロットは"メディアなし"でよい）。

### 5. 起動・再生・救出
1. `C:\Program Files\Panasonic\SD-MobileImpact\SD-MobileImpact.exe` を**管理者起動**。
   → Win7ではmirssomのクラッシュは出ない想定。ワンセグ番組一覧が出れば突破。
2. 再生できたら **VMの画面/音声をキャプチャ**して救出（OBS等でVMウィンドウを録画）。
   ワンセグは低解像度(約320×180)なので画面キャプチャで実用範囲。

## つまずいたら（チェックリスト）
- 起動で別エラー → エラーコードとイベントログ(アプリケーションエラー1000)の「障害モジュール名」を採取。
- 「マシン紐付け」でセキュア初期化失敗（再び8600系）→ VMでは厳しい。**古い実機(Win7/XP)** を検討。
- リーダー未認識 → VMのUSB互換を2.0に、ホスト側で先にリーダーのドライバ完了を待ってからConnect。
- 再生でコピー制御 → 画面キャプチャで阻止/劣化があるか確認（要実機）。

## RE（独立復号器）への発展（任意）
- 起動が通れば `SDCprm.dll` が実行時にメモリ展開される。デバッガ/メモリダンプで
  C2鍵・タイトル鍵・AKE手順（DeviceIoControl/SPTIのCDB列）を動的に採取。
- 採取結果を **WSLの `SG_IO`（usbipdでリーダーをLinuxへ）** に移植すれば、カード＋独立復号器で
  `.sb1` をオフライン復号する道が拓ける（静的解析はSDCprmがパックされ不可）。
</content>
