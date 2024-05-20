typepki-asn1parse: ASN.1 parser utility for TypePKI library
===========================================================

[TOP](https://kjur.github.io/typepki-asn1parse/) | [github](https://github.com/kjur/typepki-asn1parse) | [npm](https://www.npmjs.com/package/typepki-asn1parse) | [TypePKI](https://kjur.github.io/typepki/) 

The 'TypePKI' library is an opensource free TypeScript PKI library which is the successor of the long lived [jsrsasign](https://kjur.github.io/jsrsasign) library.

The 'typepki-asn1parse' is a ASN.1 parser utility for TypePKI library. 

## FEATURE
- ASN.1 DER parser for ASN.1 hexadecimal string (BER will also be in the future.)
- Dual CommonJS/ES module package supporting CommonJS(CJS) and ES modules

## Usage
``` JavaScript
import { asn1parse } from "typepki-asn1parse";
console.log(asn1parse("300602010a02010b"));
```
This shows
```
{
  "t": "seq",
  "v": [
    { "t": "int", "v": "0a" },
    { "t": "int", "v": "0b" },
  ]
}
```

## Parser output
Result will be a Record object which has following members:

- t - short ASN.1 tag name
- v - ASN.1 value

## short ASN.1 tag name

|short name|ASN.1 name|code|value|value sample|
|----------|----------|----|-----|------------|
|bool|INTEGER|01|||
|int|INTEGER|02|||
|bitstr|BitString|03|||
|octstr|OctetString|04|||
|null|NULL|05|||
|oid|ObjectIdentifier|06||{oid: "0.2.3.15"}|
|enum|Enumerated|0a|||
|utf8str|UTF8String|0c||{str: "りんご3"}|
|prnstr|PrintableString|13||{str: "test12"}|
|ia5str|IA5String|16||{str: "u1@example.com"}|
|utctime|UTCTime|17||131231235959Z|
|gentime|GeneralizedTime|18||20131231235959Z|
|seq|SEQUENCE|30|array of Record|[{t:"int",v:"0123"}]|
|set|SET|31|array of Record|[{t:"int",v:"0123"}]|

## Encapsulated
When the ASN.1 value is a ASN.1 TLV or a sequence of ASN.1 TLV, the V will also be parsed.

This will be applied to ASN.1 application tag TLV such as "[0]" or "[1]".



