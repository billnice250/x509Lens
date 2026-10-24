SHELL := /bin/sh
GO ?= go
PYTHON ?= python3
DIST := dist
ARCH ?=

.PHONY: all build run test test-race vet fmt check desktop desktop-installer production appstore appstore-upload clean help

all: check build

help:
	@printf '%s\n' \
		'Targets:' \
		'  make build             Build and package the native desktop app' \
		'  make run               Run the Wails desktop app' \
		'  make test              Run the Go test suite' \
		'  make test-race         Run tests with the race detector' \
		'  make vet               Run go vet' \
		'  make fmt               Format Go sources' \
		'  make check             Run fmt, vet and tests' \
		'  make desktop           Build and package the native desktop app' \
		'  make desktop-installer Build the desktop app and Windows installer' \
		'  make production        Build, sign, notarize and staple macOS DMG (uses .env)' \
		'  make appstore          Build a Mac App Store package (uses .env)' \
		'  make appstore-upload   Build and upload the App Store package (uses .env)' \
		'  make clean             Remove local build output' \
		'  ARCH=amd64|arm64|all   Select the desktop architecture'

build: desktop

run:
	go run github.com/wailsapp/wails/v2/cmd/wails@v2.17.0 dev -s -skipbindings

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

check: fmt vet test

desktop:
	$(PYTHON) scripts/build_desktop.py $(if $(ARCH),--arch $(ARCH))

desktop-installer:
	$(PYTHON) scripts/build_desktop.py $(if $(ARCH),--arch $(ARCH)) --installer

appstore:
	@set -eu; \
	if [ ! -f .env ]; then \
		echo "Missing .env; copy .env.example to .env and fill it in." >&2; \
		exit 1; \
	fi; \
	set -a; . ./.env; set +a; \
	: "$${MAC_APP_STORE_IDENTITY:?MAC_APP_STORE_IDENTITY is not set in .env}"; \
	: "$${MAC_INSTALLER_IDENTITY:?MAC_INSTALLER_IDENTITY is not set in .env}"; \
	archs="$(if $(ARCH),$(ARCH),arm64)"; \
	if [ "$$archs" = all ]; then archs="arm64 amd64"; fi; \
	for arch in $$archs; do \
		echo "==> Building Mac App Store package for $$arch"; \
		MAC_APP_STORE_IDENTITY="$$MAC_APP_STORE_IDENTITY" \
		MAC_INSTALLER_IDENTITY="$$MAC_INSTALLER_IDENTITY" \
		MAC_PROVISIONING_PROFILE="$${MAC_PROVISIONING_PROFILE:-}" \
		$(PYTHON) scripts/build_desktop.py --store --arch "$$arch"; \
	done; \
	(cd dist/desktop && shasum -a 256 X509Lens-* > SHA256SUMS)

clean:
	rm -rf $(DIST) build/bin


production:
	@set -eu; \
	if [ ! -f .env ]; then \
		echo "Missing .env; copy .env.example to .env and fill it in." >&2; \
		exit 1; \
	fi; \
	set -a; . ./.env; set +a; \
	: "$${MAC_APP_IDENTITY:?MAC_APP_IDENTITY is not set in .env}"; \
	case "$$MAC_APP_IDENTITY" in \
		"Developer ID Application:"*) ;; \
		*) echo "MAC_APP_IDENTITY must be a Developer ID Application identity." >&2; exit 1 ;; \
	esac; \
	if [ -n "$${NOTARY_PROFILE:-}" ]; then \
		:; \
	elif [ -n "$${APPLE_API_KEY_PATH:-}" ] || [ -n "$${APPLE_API_KEY_ID:-}" ] || [ -n "$${APPLE_API_ISSUER_ID:-}" ]; then \
		: "$${APPLE_API_KEY_ID:?APPLE_API_KEY_ID is not set in .env}"; \
		: "$${APPLE_API_ISSUER_ID:?APPLE_API_ISSUER_ID is not set in .env}"; \
		: "$${APPLE_API_KEY_PATH:?APPLE_API_KEY_PATH is not set in .env}"; \
		[ -f "$$APPLE_API_KEY_PATH" ] || { \
			echo "API key file not found: $$APPLE_API_KEY_PATH" >&2; \
			exit 1; \
		}; \
	else \
		: "$${APPLE_ID:?APPLE_ID is not set in .env}"; \
		: "$${APPLE_TEAM_ID:?APPLE_TEAM_ID is not set in .env}"; \
		: "$${APPLE_APP_PASSWORD:?APPLE_APP_PASSWORD is not set in .env}"; \
	fi; \
	archs="$(if $(ARCH),$(ARCH),arm64)"; \
	if [ "$$archs" = all ]; then archs="arm64 amd64"; fi; \
	for arch in $$archs; do \
		echo "==> Building macOS $$arch"; \
		MAC_APP_IDENTITY="$$MAC_APP_IDENTITY" $(PYTHON) scripts/build_desktop.py --arch "$$arch"; \
		codesign --verify --deep --strict "build/bin/X509 Lens.app"; \
		for dmg in dist/desktop/X509Lens-*-macos-"$$arch".dmg; do \
			[ -f "$$dmg" ] || continue; \
			echo "==> Notarizing $$dmg"; \
			if [ -n "$${NOTARY_PROFILE:-}" ]; then \
				xcrun notarytool submit "$$dmg" \
					--keychain-profile "$$NOTARY_PROFILE" \
					--wait; \
			elif [ -n "$${APPLE_API_KEY_PATH:-}" ]; then \
				xcrun notarytool submit "$$dmg" \
					--key "$$APPLE_API_KEY_PATH" \
					--key-id "$$APPLE_API_KEY_ID" \
					--issuer "$$APPLE_API_ISSUER_ID" \
					--wait; \
			else \
				xcrun notarytool submit "$$dmg" \
					--apple-id "$$APPLE_ID" \
					--team-id "$$APPLE_TEAM_ID" \
					--password "$$APPLE_APP_PASSWORD" \
					--wait; \
			fi; \
			xcrun stapler staple "$$dmg"; \
			xcrun stapler validate "$$dmg"; \
			spctl --assess --type open \
				--context context:primary-signature -v "$$dmg"; \
		done; \
	done; \
	(cd dist/desktop && shasum -a 256 X509Lens-*-macos-*.dmg X509Lens-*-macos-*.zip > SHA256SUMS)

appstore-upload: appstore
	@set -eu; \
	if [ ! -f .env ]; then \
		echo "Missing .env; copy .env.example to .env and fill it in." >&2; \
		exit 1; \
	fi; \
	set -a; . ./.env; set +a; \
	: "$${APPLE_API_KEY_ID:?APPLE_API_KEY_ID is not set in .env}"; \
	: "$${APPLE_API_ISSUER_ID:?APPLE_API_ISSUER_ID is not set in .env}"; \
	package=$$(ls -t dist/desktop/X509Lens-*-AppStore.pkg | head -1); \
	echo "==> Validating $$package"; \
	xcrun altool --validate-app -f "$$package" -t macos \
		--api-key "$$APPLE_API_KEY_ID" \
		--api-issuer "$$APPLE_API_ISSUER_ID"; \
	echo "==> Uploading $$package"; \
	xcrun altool --upload-app -f "$$package" -t macos \
		--api-key "$$APPLE_API_KEY_ID" \
		--api-issuer "$$APPLE_API_ISSUER_ID"
