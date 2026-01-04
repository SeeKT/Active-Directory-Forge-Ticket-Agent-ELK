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

## ログ分析
Forge Tickets のログ分析を行うスクリプトを作成。

- [GoldenTicket-Minimal.ps1](scripts/GoldenTicket-Minimal.ps1): Golden Ticket 分析用

### Golden Ticket 分析用
```
PS> powershell -ExecutionPolicy Bypass .\GoldenTicket-Minimal.ps1
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

© 2026 ktod4ts