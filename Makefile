.PHONY: help build release universal test check clean icon bundle dmg install uninstall install-service uninstall-service run dev all

PROFILE ?= release
APP = target/$(PROFILE)/HekaDrop.app
INSTALL_PATH = /Applications/HekaDrop.app

help:
	@echo "HekaDrop — make hedefleri:"
	@echo "  make build              — debug binary"
	@echo "  make release            — release binary (host mimari)"
	@echo "  make universal          — universal2 binary (Intel + ARM64)"
	@echo "  make test               — tüm cargo testleri"
	@echo "  make check              — cargo clippy + fmt kontrol"
	@echo "  make icon               — resources/icon.png → AppIcon.icns"
	@echo "  make bundle             — release + .app paketleme (+ icon varsa)"
	@echo "  make dmg                — dağıtılabilir HekaDrop-<version>.dmg"
	@echo "  make install            — bundle + /Applications altına kopyala"
	@echo "  make install-service    — launchd agent (otomatik başlatma)"
	@echo "  make uninstall-service  — launchd agent kaldır"
	@echo "  make uninstall          — service + /Applications/HekaDrop.app sil"
	@echo "  make run                — cargo run (debug)"
	@echo "  make dev                — RUST_LOG=hekadrop=debug cargo run"
	@echo "  make clean              — cargo clean + .icns temizle"
	@echo "  make all                — test + bundle"

build:
	cargo build

release:
	cargo build --release

universal:
	./scripts/build-universal.sh

test:
	cargo test

check:
	cargo clippy --all-targets -- -D warnings
	cargo fmt --check

icon:
	./scripts/make-icon.sh

bundle: release
	./scripts/bundle.sh

dmg:
	./scripts/make-dmg.sh

install: bundle
	rm -rf "$(INSTALL_PATH)"
	cp -R "$(APP)" "$(INSTALL_PATH)"
	@echo "✓ $(INSTALL_PATH) kuruldu"
	@echo "  Otomatik başlatmak için: make install-service"

uninstall: uninstall-service
	@if [ -d "$(INSTALL_PATH)" ]; then \
		rm -rf "$(INSTALL_PATH)"; \
		echo "✓ $(INSTALL_PATH) kaldırıldı"; \
	else \
		echo "Zaten yüklü değil"; \
	fi

LAUNCH_AGENT = $(HOME)/Library/LaunchAgents/com.sourvice.hekadrop.plist

install-service:
	@if [ ! -d "$(INSTALL_PATH)" ]; then \
		echo "HATA: $(INSTALL_PATH) yok. Önce: make install"; \
		exit 1; \
	fi
	mkdir -p "$(HOME)/Library/LaunchAgents"
	cp resources/com.sourvice.hekadrop.plist "$(LAUNCH_AGENT)"
	launchctl unload "$(LAUNCH_AGENT)" 2>/dev/null || true
	launchctl load -w "$(LAUNCH_AGENT)"
	@echo "✓ launchd agent yüklendi"
	@echo "  HekaDrop oturum açılışında otomatik başlar ve çökerse yeniden yüklenir."
	@echo "  Log: /tmp/hekadrop.stderr.log"

uninstall-service:
	@if [ -f "$(LAUNCH_AGENT)" ]; then \
		launchctl unload "$(LAUNCH_AGENT)" 2>/dev/null || true; \
		rm -f "$(LAUNCH_AGENT)"; \
		echo "✓ launchd agent kaldırıldı"; \
	else \
		echo "launchd agent zaten yüklü değil"; \
	fi
	@osascript -e 'tell application "System Events" to delete (every login item whose name is "HekaDrop")' 2>/dev/null || true

run:
	cargo run

dev:
	RUST_LOG=hekadrop=debug cargo run

clean:
	cargo clean
	rm -f resources/AppIcon.icns
	rm -rf resources/AppIcon.iconset

all: test bundle
