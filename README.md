# LDAPass

KeePass plugin that acts as an LDAP server. Exposes entries from an unlocked KeePass database over the LDAP protocol.

Only entries with `mailto:` or `tel:` URLs are exposed (treating KeePass as an address book).

## Build

```sh
make
```

Auto-downloads KeePass 2.61.1. To use an existing KeePass.exe:

```sh
KeePassPath=/path/to/KeePass.exe make
```

Requires Mono or .NET Framework + msbuild.

## Install

Copy `bin/Release/LDAPass.dll` into your KeePass `Plugins` directory.

## Usage

1. Open a KeePass database
2. Tools → Start LDAP Server... (enter port, default 389)
3. Query with any LDAP client:

```sh
ldapsearch -H ldap://localhost:389 -b "dc=keepass,dc=local" "(cn=*)"
```

## Entry mapping

| LDAP attribute | KeePass field |
|----------------|---------------|
| `cn`, `sn`     | Title         |
| `uid`          | UserName      |
| `userPassword` | Password      |
| `description`  | Notes         |
| `url`          | URL           |
| `ou`           | Group         |

Custom string fields are exposed as additional attributes.

## Supported operations

- Simple bind (any credentials accepted)
- Search with `equalityMatch`, `present`, `and`, `or`, `not` filters
- Attribute selection (requested attributes)
