# Analyze Active Directory Forge Ticket Logs using ELK Stack with Agent Skills
Active Directory 関連の攻撃検証およびログ監視を行うための、Agent Skills と検証結果。

## Agent Skills
[`.github/skills`](.github/skills/) 以下に作成。今回は以下構成で作成した。

```
.github/
├── skills/
│   ├── active-directory/
│   │   └── SKILL.md
│   ├── ELK/
│       └── SKILL.md
```

### 注意事項

- 現在は、VS Code Insider でのみ提供されている。Agent Skills を使う場合は `chat.useAgentSkills` を有効化する必要がある
  - Telemetry Level は off にしておくことを推奨する
- GitHub Copilot を使っている場合は、ユーザのチャットを学習されないような設定にしておく
  - Privacy > Allow GitHub to use my data for AI model training を Disabled にする
- 利用者がある程度知識があり、生成AIの出力を校閲できることが前提

### 使い方
プロンプトをもとに Agent Skills に記載された内容を読み取って Agent が回答する。専門的なタスクの場合は役立つ。

#### 利用例1: インシデント概要分析
以下のようなプロンプトを送る。

```
Active Directory に対する攻撃検証を行ったため、フォレンジックに必要な情報が取得できたか検証したい。
ELK (主に Kibana) を活用して、どのような攻撃をされた可能性があるのかを判断するものとする。

[仮定]
- 12/7 の 12:00 - 19:00 までに攻撃が起こった可能性があるということを仮定する
- チケット偽造および PtT された可能性がないかを調査したい

[要件]
- KQL 形式で検索クエリを作成し、出力すること
  - ただし、時刻は検索クエリに入れる必要はない
```

#### 利用例2: 詳細分析用スクリプトの作成
以下のようなプロンプトを送る。

```
検索結果のログを解析してもらうために、Elasticsearch API を用いてクエリを送ってログを出力するようにしたい。

[要件]
- PowerShell スクリプトで作成する
- Elasticsearchのパスワードは標準入力から読み込むようにする
- ログは、カレントディレクトリ以下に `Investigation_$timestamp` を作成して、JSON 形式および CSV 形式で出力する
```

#### 利用例3: 詳細分析 (インシデントタイムラインの作成)
出力されたログ (JSON) を添付して以下のようなプロンプトを送る。

```
これらの情報をもとに、インシデントのタイムラインを整理してほしい
```


## ログ分析
Forge Tickets のログ分析を行うスクリプトをバイブコーディングしながら作成

- [GoldenTicket-Minimal.ps1](scripts/GoldenTicket-Minimal.ps1): Golden Ticket 分析用
- [SilverTicket-Minimal.ps1](scripts/SilverTicket-Minimal.ps1): Silver Ticket 分析用
- [DiamondTicket-Minimal.ps1](scripts/DiamondTicket-Minimal.ps1): Diamond Ticket 分析用

### Golden Ticket 分析用
```
PS> powershell -ExecutionPolicy Bypass .\GoldenTicket-Minimal.ps1
```

### Silver Ticket 分析用
```
PS> powershell -ExecutionPolicy Bypass .\SilverTicket-Minimal.ps1
```

### Diamond Ticket 分析用
```
PS> powershell -ExecutionPolicy Bypass .\DiamondTicket-Minimal.ps1
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

© 2026 ktod4ts