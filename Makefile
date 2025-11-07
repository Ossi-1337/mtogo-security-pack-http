.PHONY: build test scan-fs scan-image gitleaks all

build:
	dotnet build -warnaserror -c Release

dep:
	dotnet restore

test:
	dotnet test -c Release

scan-fs:
	trivy fs --ignore-unfixed --severity HIGH,CRITICAL .

scan-image:
	docker build -t mtogo:local . && trivy image --ignore-unfixed --severity HIGH,CRITICAL mtogo:local

gitleaks:
	gitleaks detect --config=.gitleaks.toml --no-banner --redact

all: dep build test gitleaks scan-fs scan-image
