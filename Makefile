KeePassUrl := https://sourceforge.net/projects/keepass/files/KeePass%202.x/2.61/KeePass-2.61.zip/download
KeePassZip := /tmp/keepass-dl/keepass.zip
KeePassDir := /tmp/keepass-dl/extracted

all: LDAPass.dll

LDAPass.dll: BerCodec.cs Plugin.cs Server.cs LDAPass.csproj
	$(MAKE) check-dep
	msbuild LDAPass.csproj /p:Configuration=Release /p:KeePassPath="$(call get-kp)"

check: LDAPass.dll test/TestRunner.exe
	@echo "Checking plugin assembly..."
	monodis --typedef bin/Release/LDAPass.dll | grep -q "LDAPass.LDAPassExt" && echo "  [ok] LDAPassExt class found"
	monodis --typedef bin/Release/LDAPass.dll | grep -q "LDAPass.LdapServer" && echo "  [ok] LdapServer class found"
	monodis --typedef bin/Release/LDAPass.dll | grep -q "LDAPass.BerWriter" && echo "  [ok] BerWriter class found"
	monodis --typedef bin/Release/LDAPass.dll | grep -q "LDAPass.BerReader" && echo "  [ok] BerReader class found"
	@echo "Running integration tests..."
	mono test/TestRunner.exe

test/TestRunner.exe: BerCodec.cs Server.cs test/TestRunner.cs
	csc -out:test/TestRunner.exe -nologo -reference:System.dll -reference:System.Core.dll BerCodec.cs Server.cs test/TestRunner.cs

clean:
	rm -rf bin/ obj/ test/TestRunner.exe

distclean: clean
	rm -rf /tmp/keepass-dl

check-dep:
	@if ! which msbuild >/dev/null 2>&1; then echo "Error: msbuild not found (install mono-complete)"; exit 1; fi
	@if [ ! -f "$(call get-kp)" ]; then \
		echo "Downloading KeePass..."; \
		mkdir -p /tmp/keepass-dl; \
		curl -sL -o $(KeePassZip) "$(KeePassUrl)" && \
		unzip -q -o $(KeePassZip) KeePass.exe -d $(KeePassDir) && \
		echo "KeePass cached at $(KeePassDir)/KeePass.exe"; \
	fi

define get-kp
$(if $(KeePassPath),$(KeePassPath),$(KeePassDir)/KeePass.exe)
endef

.PHONY: all check clean distclean check-dep
