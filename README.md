# APT29 SIEM 實驗環境（Elasticsearch + Kibana）

把 MITRE ATT&CK Evaluations 的 **APT29 Day 1** 真實攻擊日誌，載入本機的
Elasticsearch + Kibana，並且把事件時間**平移到一個固定的時間點**
（預設 **2026-09-10 12:00**），讓講師和所有學員看到的時間軸完全一致。

- 主機日誌 196,081 筆（Sysmon / Security / PowerShell，四台 Windows 主機）
- 網路日誌 2,140 筆（Zeek，安裝時可選擇要不要載入）
- 全部跑在 localhost，不需要雲端、不需要建 Windows VM、不需要跑 agent

---

## 1. 需求

| 項目 | 說明 |
|---|---|
| Docker Desktop | 已安裝且**正在執行**，記憶體建議給 6GB 以上（Settings → Resources → Memory） |
| 磁碟空間 | 約 3GB（資料集 2GB + 索引 1GB） |
| git | macOS 可用 `xcode-select --install` |

Python 不用自己裝，`setup.sh` 會自動安裝 [uv](https://docs.astral.sh/uv/) 並處理套件。

---

## 2. 一鍵安裝

```bash
./setup.sh
```

第一次執行約 10 分鐘，絕大部分時間在下載（Docker image 與 600MB 資料集）。
腳本可以**重複執行**，中斷後直接再跑一次即可。

執行時會問一個問題：

```
  Also load the Zeek network logs (2,140 events)?
  They let students correlate host activity with network traffic.
  Load Zeek? [Y/n]
```

- 直接按 **Enter**（預設）＝ 載入主機日誌 **＋** Zeek 網路日誌
- 輸入 **n** ＝ 只載入主機日誌

想跳過詢問（例如寫在其他腳本裡）可以直接加參數：

```bash
./setup.sh --zeek       # 一定載入 Zeek
./setup.sh --no-zeek    # 一定不載入 Zeek
```

> 選 `--no-zeek` 之後如果之前載過 Zeek，舊的 Zeek 索引會被刪掉。
> 因為時間重新平移後，舊索引的時間會對不上主機事件。
> 之後想補上，再跑一次 `./setup.sh --zeek` 即可。

跑完會看到：

```
Lab is ready.  Events are replayed at 2026-09-10 12:00 Asia/Taipei (fixed date)

  Kibana     http://localhost:5601
  Discover   http://localhost:5601/app/discover
  Time range set the Kibana time picker to this absolute range:
             Sep 10, 2026 @ 12:00:00.000 -> Sep 10, 2026 @ 12:40:00.000
```

最後那個**時間範圍請直接複製**，貼到 Kibana 右上角的時間選擇器
（選 **Absolute**）。這樣大家的畫面會一模一樣。

### 其他指令

| 指令 | 用途 |
|---|---|
| `./setup.sh` | 建立環境（可重複執行） |
| `./setup.sh --reshift` | **依照 `lab.conf` 的設定重新平移時間**。改過 `ANCHOR_*` 之後跑這個（容器沒開會自動幫你開，不用先跑 `./setup.sh`） |
| `./setup.sh --zeek` / `--no-zeek` | 指定要不要載入 Zeek 網路日誌，不再詢問 |
| `./setup.sh --down` | 關掉容器，**資料保留** |
| `./setup.sh --clean` | 關掉容器並**刪除所有資料** |

以上參數可以合併使用，例如只要主機日誌：
`./setup.sh --reshift --no-zeek`

---

## 3. 開始查資料

打開 <http://localhost:5601> → 左上角選單 → **Discover** → 資料檢視選
**APT29 lab**。

> **以下日期是 `lab.conf` 的預設值（`ANCHOR_DATE=2026-09-10`）。**
> 如果你改過 `ANCHOR_DATE`，請自行換成你設定的日期 ——
> `./setup.sh` 跑完會印出當下正確的絕對時間範圍與連結，以那個為準。

> **右上角時間範圍要自己設。**
> Kibana 預設是「Last 15 minutes」，那個區間沒有資料，畫面會是空的。
> 資料固定落在 **2026-09-10 12:00 – 12:40**（Asia/Taipei），
> 時間選擇器選 **Absolute** 並貼上：
> `Sep 10, 2026 @ 12:00:00.000` → `Sep 10, 2026 @ 12:40:00.000`

幾個可以直接貼上的 KQL 查詢：

```
# 程序建立（攻擊鏈的主軸，共 446 筆）
event.category:"process" and event.type:"start"

# 最初的惡意程式：偽裝成螢幕保護程式的 cod.3aka3.scr
process.name:*3aka3*

# WebDAV 相關活動（下載與外傳）
CommandLine:*webdav* or TargetFilename:*webdav*

# PowerShell script block 紀錄
EventID:(4103 or 4104)

# 登錄檔持續化：COM hijacking
TargetObject:*shell\\open\\command*

# Zeek 網路事件（需要在安裝時選擇載入 Zeek）
agent.type:"zeek"

# Zeek HTTP（可看到把 OfficeSupplies.7z PUT 出去的外傳行為）
agent.type:"zeek" and zeek.stream:"http"
```

### 程序樹（visual event analyzer）

程序樹**不在 Discover**，在 Security app 裡。步驟：

1. 左側選單 **Security → Explore → Hosts**，選 **Events** 分頁
2. 右上角時間範圍設成 `Sep 10, 2026 @ 12:00:00.000` → `Sep 10, 2026 @ 12:40:00.000`
3. 查詢列貼上（找出最初的惡意程式）：
   ```
   process.name:*3aka3* and event.category:"process" and event.type:"start"
   ```
4. 往下捲到 **Events** 表格，把游標移到那一列左邊的小圖示上，
   點提示文字是 **Analyze event** 的那一個（第 4 個圖示）
   > 旁邊那個很像的是 **Investigate in timeline**，點錯只會開 Timeline，不是程序樹
5. 右側會滑出 flyout → **Visualize** 分頁 → 按 **Analyzer Graph**

也可以直接貼這個網址（已經帶好查詢與時間範圍；
`./setup.sh` 跑完也會印出這個連結）：

```
http://localhost:5601/app/security/hosts/events?sourcerer=(default:(id:security-solution-default,selectedPatterns:!('winlogbeat-apt29-*')))&timerange=(global:(linkTo:!(timeline),timerange:(from:%272026-09-10T04:00:00.000Z%27,kind:absolute,to:%272026-09-10T04:40:00.000Z%27)),timeline:(linkTo:!(global),timerange:(from:%272026-09-10T04:00:00.000Z%27,kind:absolute,to:%272026-09-10T04:40:00.000Z%27)))&query=(language:kuery,query:'process.name:*3aka3* and event.category:"process" and event.type:"start"')
```

畫出來的程序樹（用滾輪縮放、可拖曳；節點下方的 `1 file` / `65 library` /
`3 network` 是掛在該程序上的相關事件）：

```
explorer.exe                          ← 往上追到的父程序
└─ (RTLO 偽裝) cod.3aka3.scr          ← Analyzed Event，pbeesly 雙擊執行
   ├─ conhost.exe
   └─ cmd.exe
      └─ powershell.exe
         └─ sdclt.exe                 ← UAC bypass
            └─ control.exe
               └─ powershell.exe -noni -noexit -ep bypass -window hidden
```

> **Session View** 那個切換頁在本環境是空的，它需要 Elastic Endpoint 的資料，
> Sysmon 沒有。要看程序樹請用 **Analyzer Graph**。

這是本環境特別做 ECS 對應的目的：Sysmon 的 `ProcessGuid` / `ParentProcessGuid`
被對應成 `process.entity_id` / `process.parent.entity_id`。

---

## 4. 資料長什麼樣子

**原始欄位全部保留**（`Image`、`CommandLine`、`TargetObject`、`EventID` … 都是
Windows/Sysmon 原生名稱），ECS 欄位是**額外加上去**的，兩種都查得到。

| 索引 | 內容 | 筆數 |
|---|---|---|
| `winlogbeat-apt29-host-day1` | 主機日誌 | 196,081 |
| `winlogbeat-apt29-zeek-day1` | Zeek 網路日誌（可選） | 2,140 |

主機分布：SCRANTON 131,119 / NASHUA 29,056 / NEWYORK 23,935 / UTICA 11,971。

四台主機都在 `dmevals.local` 網域，攻擊從 SCRANTON 上的使用者 `pbeesly`
雙擊 `cod.3aka3.scr` 開始。

---

## 5. 已知地雷（重要，請先看過）

**時間相關**

1. **資料已平移到固定時間 2026-09-10 12:00**（台北時間）。原始時間保留在
   `@timestamp_original`、`UtcTime_original`、`EventTime_original`，
   原始區間是 2020-05-02 02:55–03:28 UTC。
   因為是**固定日期**，不管哪天安裝，時間軸都一樣，講師和學員可以對照同一個畫面。
   代價是時間選擇器**不能用「Today」**，要用上面那個絕對範圍。
2. **`EventTime` 比 `UtcTime` 慢 4 小時**。這是原始資料的性質（端點本地時間 UTC-4），
   不是 bug，平移後刻意保持這個差距。
3. **Zeek 的原始時鐘和主機差了兩天**（Zeek 是 2020-04-30、主機是 2020-05-02）。
   兩邊是同一場攻擊、不同時鐘。因此兩個載入程式共用同一個「錨點」
   （今天 09:00），但**各自計算位移量**，讓主機與網路事件落在同一個時間軸上。
   位移量都記錄在 `data/shift_delta.json`。

**資料本身**

4. **Channel 大小寫不一致**：原始資料同時有 `Security` 與 `security`，
   載入時已正規化成 `Security`，原值保留在 `Channel_raw`。
   沒做這件事的話按 Channel 過濾會少 12,375 筆。
5. **`EventType` 沒有 Sysmon 的原意**。NXLog 把 Sysmon 的
   `CreateKey` / `SetValue` / `DeleteKey` 蓋掉了，全部 61,152 筆 EID 12 的
   `EventType` 都是 `INFO`。**依賴 `EventType` 的 Sigma 規則在這份資料上永遠不會命中**，
   要改用 `EventID` 判斷。
6. **原始欄位 `host` 與 ECS 的 `host.*` 衝突**。`host`（WEC 收集器名稱）和 Zeek 的
   `source`（檔案來源協定）都是純字串，和 ECS 物件撞名，載入時改名為
   `host_raw`、`source_raw`。
7. **OTRF repo 裡 `datasets/day1/README.md` 的統計表與實際檔案對不上**
   （README 寫 Sysmon 164,435、EID 1 為 433）。本專案所有數字都是對實際檔案數出來的。
8. **這批資料沒有一般使用者的背景噪音**，是乾淨測試環境加紅隊動作。
   教學時要講明，不要宣稱它代表真實企業的訊噪比。
9. pcap 在 `data/detection-hackathon-apt29/datasets/day1/pcaps/`，zip 密碼 `infected`。

**環境設定**

10. **索引名稱不能用 `logs-` 開頭**。Elasticsearch 內建的 `logs` template 匹配
    `logs-*-*` 且只允許建 data stream，用那種名字會直接被拒絕。
    另外索引一定要落在 `winlogbeat-*`，Elastic Security 的預設 data view 才看得到，
    Analyze event 也才點得出來。Zeek 資料與 winlogbeat 無關，但同樣掛在
    `winlogbeat-` 前綴下就是這個原因。
11. **`process.entity_id` 必須是 `keyword`**。被 dynamic mapping 判成 `text` 的話，
    程序樹會**安靜地失效**，不會報錯。index template 已明確指定。
12. **ECS 欄位在 `_source` 裡必須是巢狀物件，不能是扁平的點號 key**。
    寫成 `{"process.entity_id": "..."}` 的話，Elasticsearch 查詢完全正常
    （點號路徑在查詢時會被解析），連程序樹都畫得出來（樹是後端算的），
    但 Kibana 前端是用 `event.process?.entity_id` 讀 `_source`，讀不到，
    於是**點任何節點都會顯示「Node details were unable to be retrieved」**。
    載入程式會把 ECS 欄位轉成巢狀物件（`scripts/ecs_mapper.py` 的
    `nest_ecs_fields()`），`verify.py` 也有對應檢查。
    原始 Windows 欄位名稱都沒有點號，維持扁平不受影響。
13. **EID 10（39,283 筆）與 EID 12（61,151 筆）預設不做 ECS process 對應**，
    否則程序樹會被洗到看不清。原始欄位照樣寫入、照樣查得到，只是不掛
    `process.entity_id`。需要時用 `--ecs-process-eid 10` 打開。
14. **本環境關閉了 Elasticsearch 安全性**（`xpack.security.enabled=false`），
    純本機教學用，省掉憑證與帳號。Kibana 會跳「Your data is not secure」提示，
    直接關掉即可。**不要把這個設定用在對外環境。**

---

## 6. 檔案結構

```
.
├── setup.sh                        # 一鍵安裝（主要入口）
├── docker-compose.yml              # Elasticsearch 8.19.21 + Kibana 8.19.21
├── lab.conf                        # ★ 設定檔：時間錨點、Elastic 版本、連線位址
├── elastic/
│   ├── index-template-host.json    # 主機索引 mapping
│   └── index-template-zeek.json    # Zeek 索引 mapping
├── scripts/
│   ├── fetch_dataset.py            # 下載資料集並逐 byte 驗證
│   ├── ecs_mapper.py               # 時間平移 + ECS 對應邏輯
│   ├── load_host_events.py         # 載入主機事件
│   ├── load_zeek.py                # 載入 Zeek 事件
│   └── verify.py                   # 33 項驗收檢查
└── data/                           # 資料集與 shift_delta.json（不進版控）
```

### 調整設定

改 `lab.conf`（專案根目錄，直接編輯，不用複製範本）：

```bash
ANCHOR_DATE=2026-09-10    # 平移後的日期；改成 today 就會跟著安裝當天跑
ANCHOR_LOCAL=12:00        # 平移後第一筆事件的時間
ANCHOR_TZ=Asia/Taipei     # 時區
STACK_VERSION=8.19.21     # Elastic 版本（已固定，換版本要自行確認 UI 路徑）
ES_JAVA_OPTS=-Xms2g -Xmx2g
ES_URL=http://localhost:9200
KIBANA_URL=http://localhost:5601
```

`lab.conf` 裡面**沒有任何密碼或金鑰**，可以直接進版控、直接發給學員，
不需要像 `.env` 那樣先複製範本。

改完跑 `./setup.sh --reshift` 生效，畫面會印出新的絕對時間範圍。

- `ANCHOR_DATE=2026-09-10`（預設）→ 固定時間軸，**全班畫面一致**，
  但時間選擇器要用絕對範圍。
- `ANCHOR_DATE=today` → 資料永遠落在安裝當天，時間選擇器可以直接用
  「Today」，但每個人跑的日子不同、畫面就不同。

---

## 7. 驗收

`./setup.sh` 最後會自動跑 40 項檢查（文件數、主機分布、Channel 正規化、
時間平移、ECS 欄位、mapping 型別）。全數通過才算成功。
沒有載入 Zeek 時，其中 2 項會顯示 `SKIP`，剩下 38 項要全過。

也可以單獨執行：

```bash
uv run scripts/verify.py            # 有載入 Zeek
uv run scripts/verify.py --no-zeek  # 沒有載入 Zeek
```

有兩項腳本測不了（畫面渲染）、**要用眼睛確認**：
Security → Explore → Hosts → Events，時間設成
`Sep 10, 2026 @ 12:00:00.000` → `Sep 10, 2026 @ 12:40:00.000`，
用 `event.category:"process" and event.type:"start"` 過濾，點 **Analyze event**：

1. 程序樹要畫得出來，往上追得到祖先、往下展得開子程序
2. **點任一個節點，右側詳細資料要跑出來**（host.name、process.executable…）。
   如果顯示「Node details were unable to be retrieved」，
   代表 ECS 欄位又變回扁平點號 key 了，見第 5 節第 12 點。

---

## 8. 疑難排解

| 症狀 | 處理 |
|---|---|
| Kibana 打不開 / 一直轉 | Kibana 啟動要 1–3 分鐘。`docker compose logs kibana` 看狀態 |
| 畫面沒有資料 | 時間範圍改成上面的絕對範圍（預設 Last 15 minutes 是空的） |
| 找不到資料 | 時間範圍要設成 `Sep 10, 2026 @ 12:00` → `12:40`（不是 Today） |
| 改了 `lab.conf` 沒生效 | 要跑 `./setup.sh --reshift` 重新載入 |
| Elasticsearch 啟動後就掛掉 | 多半是記憶體不足，Docker Desktop 調到 6GB 以上 |
| 想從頭重來 | `./setup.sh --clean` 然後 `./setup.sh` |
| port 9200 / 5601 被占用 | 先關掉佔用的服務，或改 `docker-compose.yml` 的 port 對應 |

---

## 9. 資料來源與授權

- 資料集：[OTRF/detection-hackathon-apt29](https://github.com/OTRF/detection-hackathon-apt29)（GPL-3.0）
- 情境：[MITRE ATT&CK Evaluations — APT29](https://attackevals.mitre-engenuity.org/)
