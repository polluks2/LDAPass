KeePassPath ?= /path/to/KeePass.exe

all: LDAPass.dll

LDAPass.dll: BerCodec.cs Plugin.cs Server.cs LDAPass.csproj
	KeePassPath=$(KeePassPath) msbuild LDAPass.csproj /p:Configuration=Release

check: LDAPass.dll
	@echo "Checking plugin assembly..."
	monodis --typedef bin/Release/LDAPass.dll | grep -q "LDAPass.LDAPassExt" && echo "  [ok] LDAPassExt class found"
	monodis --typedef bin/Release/LDAPass.dll | grep -q "LDAPass.LdapServer" && echo "  [ok] LdapServer class found"
	monodis --typedef bin/Release/LDAPass.dll | grep -q "LDAPass.BerWriter" && echo "  [ok] BerWriter class found"
	monodis --typedef bin/Release/LDAPass.dll | grep -q "LDAPass.BerReader" && echo "  [ok] BerReader class found"
	@echo "All checks passed."

clean:
	rm -rf bin/ obj/

.PHONY: all check clean
