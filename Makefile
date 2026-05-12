KeePassPath ?= /path/to/KeePass.exe

all: LDAPass.dll

LDAPass.dll: BerCodec.cs Plugin.cs Server.cs LDAPass.csproj
	KeePassPath=$(KeePassPath) msbuild LDAPass.csproj /p:Configuration=Release

clean:
	rm -rf bin/ obj/

.PHONY: all clean
