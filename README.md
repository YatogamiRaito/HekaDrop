# HekaDrop

Android'den Mac/Linux/Windows'a dosya gönder. Telefona uygulama kurma, bulut yok, hesap yok.

[![CI](https://github.com/YatogamiRaito/HekaDrop/actions/workflows/ci.yml/badge.svg)](https://github.com/YatogamiRaito/HekaDrop/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/YatogamiRaito/HekaDrop?display_name=tag&sort=semver)](https://github.com/YatogamiRaito/HekaDrop/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Google Quick Share protokolünün Rust implementasyonu. Android'deki stock Quick Share ile çalışır.

## Kurulum

**macOS**
```bash
brew install --cask yatogamiraito/tap/hekadrop
```

**Linux / Windows** → [Releases](https://github.com/YatogamiRaito/HekaDrop/releases/latest)

**Kaynaktan**
```bash
git clone https://github.com/YatogamiRaito/HekaDrop && cd HekaDrop
make install
```

## Kullanım

1. HekaDrop'u başlat — menü çubuğunda `⇄` simgesi belirir.
2. Android'de *Paylaş → Quick Share* → listeden HekaDrop'u seç.
3. 4 haneli PIN'i karşılaştır → **Kabul et**.

Dosya göndermek için pencereye sürükle ya da **Dosya gönder…** menüsünü kullan.

## Platform Desteği

| Platform | Durum |
|---|---|
| macOS (Intel + Apple Silicon) | ✅ |
| Linux (GTK3) | ✅ |
| Windows | ✅ |

## Geliştirme

```bash
make test
cargo clippy --all-targets -- -D warnings
```

[CONTRIBUTING.md](CONTRIBUTING.md) · [ROADMAP](docs/ROADMAP.md) · [MIT](LICENSE)
