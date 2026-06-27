# SO-05F ETS フォーマット・DRM 解析

対象: Sony Xperia Z2 Tablet docomo (SO-05F) の StationTV! (富士ソフト) 録画ファイル  
解析日: 2026-06-27

---

## 1. ETS ファイル構造

### 1-1. コンテナ形式

**ETS = 標準 M2TS 形式**（ファイルレベル暗号化なし）

```
ETS = 192B × N M2TS パケット（オフセット 0 から開始）
  各パケット = [4B ARIBタイムスタンプ] + [188B TS パケット]
```

### 1-2. ファイル一覧とビットレート断定

| ファイル | サイズ | 時間 | ビットレート | 分類 |
|---------|--------|------|------------|------|
| MPG001/MMV001.ETS | 2.2MB | 47s | 0.38 Mbps | **ワンセグ** (ISDB-T 1seg) |
| MPG002/MMV001.ETS | 3.1MB | 58s | 0.42 Mbps | **ワンセグ** |
| MPG003/MMV001.ETS | 14.7MB | 17s | 6.94 Mbps | **フルセグ** (ISDB-T 13seg) |
| MPG004/MMV001.ETS | 60.9MB | 32s | 15.24 Mbps | **フルセグ** |
| MPG005/MMV001.ETS | 44.2MB | 41s | 8.63 Mbps | **フルセグ** |
| MPG006/MMV001.ETS | 20.6MB | 20s | 8.26 Mbps | **フルセグ** |
| MPG007/MMV001.ETS | 0B | 4s | — | 空/エラー |
| MPG008/MMV001.ETS | 336MB | 212s | 12.69 Mbps | **フルセグ（最大）** |

**断定根拠（3条件一致）**:
- ビットレート: ワンセグ ≈ 0.4 Mbps / フルセグ ≈ 8〜17 Mbps
- Marlin DRM: ワンセグ=CA_descriptor なし / フルセグ=CA_sys 0x4AF4
- PID 系統: ワンセグ=0x028x/0x058x 系 / フルセグ=0x0111/0x0C1x 系

### 1-3. 付属ファイルの役割

| 拡張子 | 内容 |
|--------|------|
| `.ETS` | 録画コンテンツ本体（192B M2TS） |
| `.MMA` | 音声メタデータ（28B固定長） |
| `.MMO` | 録画メタデータ（1036B、タイムスタンプ等） |
| `.MPI` | 再生リスト情報（タイトル・タイムコード） |

---

## 2. PID 構成

### 2-1. Clear PID（全ファイル共通）

| PID | 内容 |
|-----|------|
| `0x0000` | PAT（フルセグのみ） |
| `0x001F` | SIT（Selection Information Table） |
| `0x1FC8` | **ETS 固有 DRM メタ PMT**（Marlin CA 情報） |
| `0x05FF` or `0x0100` | PCR |

### 2-2. PID 0x1FC8（DRM メタ PMT）

PAT でのマッピング: プログラム 3480 (0x0D98) → PMT PID 0x1FC8

**ワンセグ PMT（prog 0x8580）**:
```
PCR_PID: 0x05FF
program_info_length: 3B
  desc 0xC1(1B): 0x88  ← 富士ソフト独自フラグ
Streams:
  0x1B(H.264)  PID=0x0581  ← ワンセグ映像
  0x0F(AAC)    PID=0x0583  ← ワンセグ音声
  0x06(Private) PID=0x0587  ← 字幕
  0x0D(Data)   PID=0x0580,0x0589-0x058B
```
**CA_descriptor なし** → Marlin DRM 非適用（ただしコンテンツはスクランブル済み）

**フルセグ PMT（prog 0x0C18 等）**:
```
PCR_PID: 0x0100 または 0x01FF
program_info_length: 120B
  CA_descriptor (tag=0x09, 118B):
    CA_system_id: 0x4AF4  ← Marlin DRM (Sony SEMC)
    CA_PID:       0x0001
    private_data (114B):  ← Marlin ライセンス情報（後述）
Streams: なし（Marlin ライセンス管理）
```

---

## 3. Marlin DRM 詳細（フルセグ）

### 3-1. CA private_data 構造（114B）

```
\x02\x00\x01 + ASCII:
  nsemc-import:urn:marlin:organization:semc:licensesign:
  000700010114cb8b:
  <content_id (40桁10進数, 録画ごとに固有>
```

| フィールド | 値 | 意味 |
|-----------|-----|-----|
| `nsemc-import` | 固定 | Sony SEMC Marlin ライセンスインポート |
| `urn:marlin:organization:semc` | 固定 | Sony SEMC 組織 URI |
| `000700010114cb8b` | **全ファイル共通** | デバイス/モデル固有 ID |
| `<content_id>` | 録画固有 | コンテンツライセンス識別子 |

各録画の content_id:

| 録画 | content_id |
|------|-----------|
| MPG003 | `5392370535524993621672029097206749352495` |
| MPG004 | `9804269605137753104639392562652256649889` |
| MPG005 | `9152970999746559227230041657482925198053` |
| MPG006 | `5312532595902795683290827291008727372019` |
| MPG008 | `7060827625317993780899718766410030825645` |

### 3-2. TSC=3 解析（重要）

**全ファイル・全 PID で TSC=2(偶数鍵)=0、TSC=3(奇数鍵)のみ使用**

→ Multi2 スクランブルではない（Multi2 は偶奇交互）  
→ **TSC=3 は DRM 保護フラグとして流用**  
→ 実際の暗号: AES-128-CTR/CBC（NSNP API 経由）

---

## 4. 暗号スタック（確定）

```
StationTV → libodekakeplugin.so (お出かけ DRM, /system/lib/drm/)
              → libnpfinal.so (NSNP/Madai API)
                 ↓ nsnp_DecryptWithOffsetRegions
                 → nssmi_DecryptWithOffsetRegions (offset 0x23E04, 210B)
              → libkeyctrl.so (DX_keyctrl_* = Discretix)
                 → libQSEEComAPI.so → TrustZone (ハードウェアキー)
```

**主要 API**:
- `nsnp_InitTrack` / `nsnp_CreateTrack` / `nsnp_CreateCK` → コンテンツキー生成
- `nsnp_DecryptWithOffsetRegions` (stub 12B) → `nssmi_DecryptWithOffsetRegions` (210B)
- `nsnp_bbtsParseCADescriptor` → ETS PMT の CA descriptor 解析
- `nsnp_bbtsInitECMStream` → 放送 ECM ストリーム初期化
- `DX_keyctrl_SessionOpen/Close` / `DX_keyctrl_Sign` → Discretix TrustZone 連携

**ライセンス DB**: `/data/drm/odekake/odekakedatabase.db` (SQLite, UID=drm 専用)

### 4-1. 実機での DRM ライブラリ (SO-05F /system/lib/drm/)

| ファイル | サイズ | 役割 |
|---------|--------|-----|
| libodekakeplugin.so | 424KB | お出かけ DRM メインプラグイン |
| libmarlinplugin.so | 524KB | Marlin DRM プラグイン |
| libacdrmengine.so | 59KB | AC DRM |
| libfwdlockengine-semc.so | 252KB | OMA FwdLock (Sony) |
| libmsdrmpiffengine.so | 108KB | MS DRM PIFF |
| libomasdengine.so | 260KB | OMA SecureDownload |

### 4-2. 依存ライブラリ (libodekakeplugin.so → libnpfinal.so → libkeyctrl.so)

```
libodekakeplugin.so NEEDED:
  libsqlite.so, libcrypto.so, libssl.so, libcurl.so
  libnpfinal.so, libsapporo.so, libkeyctrl.so

libnpfinal.so NEEDED:
  libcrypto.so, libQSEEComAPI.so  ← TrustZone
  libkeyctrl.so, libsapporo.so

libkeyctrl.so exports:
  DX_keyctrl_Startup/Shutdown
  DX_keyctrl_Sign / DX_keyctrl_SessionOpen/Close
  DX_keyctrl_GetDeviceCertChain / GetRootCertificate / GetWhiteList
```

---

## 5. SO-05F デバイス情報（ADB 接続確認）

| 項目 | 値 |
|------|-----|
| Model | SO-05F (Xperia Z2 Tablet docomo) |
| Android | 4.4.2 |
| Build | 17.1.1.B.3.195 |
| Kernel | 3.4.0-perf-g699539a (2014-08-20) |
| SoC | Qualcomm MSM8974PRO-AB (Snapdragon 800) |
| CPU arch | ARMv7 |

**CVE-2016-5195 (Dirty COW) 状況**: カーネル 3.4.0 (2014年) は未パッチ。  
SH-06F 用 dirtycow2 バイナリが SO-05F で動作確認済み。

---

## 6. 復号への道筋

### フルセグ ETS 復号

```
1. SO-05F root 化 (Dirty COW on libodekakeplugin.so + drmserver)
2. drmserver (UID=drm) として /data/drm/odekake/odekakedatabase.db を読む
3. content_id でライセンスを特定
4. TrustZone ベースのキーを nsnp_DecryptWithOffsetRegions で使用
   OR: nssmi_DecryptWithOffsetRegions を hook して出力をキャプチャ
5. 復号済み M2TS を保存
```

### ワンセグ ETS 復号

- TSC=3 スクランブルが何で暗号化されているか未確定
- PMT に CA descriptor なし → ECM PID 不明
- 同じく NSNP API 経由の可能性が高い
- ETS 再生中に nssmi_DecryptWithOffsetRegions を hook

---

## 7. android_libs 内のファイル帰属

`PRIVATE/android_libs/` には以下が混在（要整理）:

**SH-06F 由来** (ADB pull):
- `libMmb*.so`, `MmbCaCasDrmMw`, `MmbFcLiceMwServer`, `MmbFcCtlMw`

**SO-05F 由来** (SD カード PRIVATE/android_libs/):
- `libDxDrmServer.so`, `libDxCprm.so` (Discretix)
- `libstationtv_lt_co_*.so`, `stationtv.apk` (StationTV)
- `fsegsaveservice`, `libshfsegsave*.so` (フルセグ save)
- `libsceseccnt.so`, `libscecommon.so`, `libscesender.so` (SCE = Sony)
- `libshcprm.so`, `libshsd.so`, `libshfullseg_keyprov.so`

**不明（どちらも持つ可能性）**:
- `libm2tslib.so`, `libseccntmng.so`
