# DS

[![Go Report Card](https://goreportcard.com/badge/github.com/tls-inspector/authrootstl?style=flat-square)](https://goreportcard.com/report/github.com/tls-inspector/authrootstl)
[![Godoc](https://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](https://pkg.go.dev/github.com/tls-inspector/authrootstl)
[![Releases](https://img.shields.io/github/release/tls-inspector/authrootstl/all.svg?style=flat-square)](https://github.com/tls-inspector/authrootstl/releases)
[![LICENSE](https://img.shields.io/github/license/tls-inspector/authrootstl.svg?style=flat-square)](https://github.com/tls-inspector/authrootstl/blob/master/LICENSE)

This package provides a interface to parse & validate Microsoft Windows authroot.stl file
which contains the list of participants in the Microsoft Trusted Root Program. The trust list
file contains so-called "subjects", which describe a certificate, their accepted use within Windows,
and their trust status.

# Usage & Examples

Examples can be found on the [documentation for the library](https://pkg.go.dev/github.com/tls-inspector/authrootstl)

## License

Mozilla Public License Version 2.0.

This package embeds a modified version of [github.com/mozilla-services/pkcs7](https://github.com/mozilla-services/pkcs7). This package is not affiliated with or endorsed by Microsoft. Windows is a registered trademark of Microsoft Corporation.