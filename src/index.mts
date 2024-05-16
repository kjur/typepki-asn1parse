import { ishex, strpad, hextouricmp, hextoutf8 } from "typepki-strconv";

/**
 * parse ASN.1 hexadecimal string
 * @param h - ASN.1 hexadecimal string
 * @return parsed ASN.1 as Record object
 * @example
 * asn1parse("300602010a02010b") -> {
 *  t: "seq",
 *  v: [
 *    { t: "int", v: "0a" },
 *    { t: "int", v: "0b" },
 *  ]
 * }
 */
export function asn1parse(h: string): Record<string, any> {
  let p: Record<string, any> = {};
  const hT = getTh(h, 0);
  const tag = taghextos(hT);
  const hL = getLh(h, 0);
  const iL = lenhextoint(hL);
  let value: string | Record<string, any> = getVh(h, 0);
  if (["seq", "set", "a0", "a3"].includes(tag)) {
    const aList = getDERTLVList(h, hT.length + hL.length, iL * 2);
    value = aList.map((hItem) => asn1parse(hItem));
  }
  if (["octstr"].includes(tag) && isDER(h)) {
    try {
      value = { "asn": asn1parse(value as string) };
    } catch (ex) {
      value = { "hex": value };
    }
  }
  if (["prnstr"].includes(tag)) {
    try {
      value = { "str": hextoutf8(value as string) };
    } catch (ex) {
      value = { "hex": value };
    }
  }
  if (["oid"].includes(tag)) {
    try {
      const oid = oidtoname(hextooid(value as string));
      value = { "oid": oid };
      console.log("oid=", oid);
    } catch (ex) {
      value = { "hex": value };
    }
  }
  if (["utctime", "gentime"].includes(tag)) {
    try {
      value = hextoutf8(value as string);
    } catch (ex) {
      value = { "hex": value };
    }
  }
  if (tag.slice(0, 1) == "8") {
    try {
      value = { str: hextoutf8(value as string) };
    } catch (ex) {
      value = { "hex": value };
    }
  }

  return {
    t: tag,
    v: value
  };
}

/*
 */

const OIDDB: Record<string, string> = {
  "1.2.840.10045.2.1": "ecPublicKey",
  "1.2.840.10045.3.1.7": "prime256v1",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.3.6.1.4.1.11129.2.4.2": "extendedValidationCertificates",
  "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
  "1.3.6.1.5.5.7.3.1": "serverAuth",
  "1.3.6.1.5.5.7.3.2": "clientAuth",
  "1.3.6.1.5.5.7.48.1": "ocsp",
  "1.3.6.1.5.5.7.48.2": "caIssuers",
  "2.23.140.1.2.1": "cabfBrDomainValidated",
  "2.5.29.14": "subjectKeyIdentifier",
  "2.5.29.15": "keyUsage",
  "2.5.29.17": "subjectAltName",
  "2.5.29.19": "basicConstraints",
  "2.5.29.32": "certificatePolicies",
  "2.5.29.35": "authorityKeyIdentifier",
  "2.5.29.37": "extKeyUsage",
  "2.5.4.10": "organizationName",
  "2.5.4.3": "commonName",
  "2.5.4.6": "countryName",
};

export function oidtoname(oid: string): string {
  if (oid in OIDDB) return OIDDB[oid];
  return oid;
}

export function taghextos(h: string): string {
  if (h === "01") return "bool";
  if (h === "02") return "int";
  if (h === "03") return "bitstr";
  if (h === "04") return "octstr";
  if (h === "05") return "null";
  if (h === "06") return "oid";
  if (h === "0a") return "enum";
  if (h === "0c") return "utf8str";
  if (h === "13") return "prnstr";
  if (h === "16") return "ia5str";
  if (h === "17") return "utctime";
  if (h === "18") return "gentime";
  if (h === "30") return "seq";
  if (h === "31") return "set";
  return h;
}

export function getTLVh(h: string, sidx: number): string {
  const hT = getTh(h, sidx);
  const hL = getLh(h, sidx);
  const hV = getVh(h, sidx);
  return `${hT}${hL}${hV}`;
}

export function getTh(h: string, sidx: number): string {
  return h.slice(sidx, sidx + 2);
}

/**
 * get ASN.1 length(L) octets for specified string index
 * @param h - supposed ASN.1 hexadecimal string
 * @param sidx - string index of ASN.1 TLV to get
 * @return hexadecimal string of ASN.1 octets
 * @example
 * @getLh("0203010203", 0) -> "03"
 * @getLh("...040208ba", 3) -> "02" // TLV starts with 04020108...
 * @getLh("0282034f03...", 0) -> "82034f"
 * @getLh("02800203...", 0) -> "80" // ASN.1 BER infinite length
 */
export function getLh(h: string, sidx: number): string {
  let hL0: string = "";
  try {
    hL0 = h.slice(sidx + 2, sidx + 4);
    const iL0 = Number.parseInt(hL0, 16);
    if (Number.isNaN(iL0)) throw new Error("NaN");
    //console.log("iL0=", iL0);
    if (iL0 < 128) return hL0;
    const nLbyte = iL0 & 127;
    //console.log("nLbyte=", nLbyte);
    return h.slice(sidx + 2, sidx + 2 + 2 + nLbyte * 2);
  } catch (ex) {
    throw new Error(`can't get ASN.1 L octets: L=${hL0}...`);
  }
}

export function lenhextoint(hL: string): number {
  if (hL === "80") return -1;
  const iL0 = Number.parseInt(hL.slice(0, 2), 16);
  if (iL0 < 128) return iL0;
  if ((iL0 & 127) !== (hL.length / 2 - 1)) {
    throw new Error(`malformed ASN.1 L octets: ${hL}`);
  }
  return Number.parseInt(hL.slice(2), 16);
}

export function getVh(h: string, sidx: number): string {
  const hL = getLh(h, sidx);
  const iL = lenhextoint(hL);
  if (iL === -1) {
    throw new Error("BER indefinite length not supported yet");
  }
  return h.slice(sidx + 2 + hL.length, sidx + 2 + hL.length + iL * 2);
}

/**
 * get array of hexadecimal TLV at specified string index
 * @param h - hexadecimal stirng
 * @param sVLidx - string index of the first TLV
 * @param slen - string length of TLV list
 * @return array of hexadecimal TLV
 */
export function getDERTLVList(h: string, sVLidx: number, slen: number): string[] {
  let a: string[] = [];
  let offset = 0;
  while (offset < slen) {
    const hi = getTLVh(h, sVLidx + offset);
    a.push(hi);
    offset += hi.length;
  }
  if (offset != slen) {
    throw new Error("wrong sVLidx or slen");
  }
  return a;
}

/**
 * check if the string is ASN.1 DER hexadecimal string
 * @param h - string
 * @return return true if the string is a ASN.1 DER hexadecimal string
 * @example
 * isDER("020201ab") -> true
 * isDER("zzz") -> false // not hexadecimal
 * isDER("020201") -> false // too short
 * isDER("020201abcd") -> false // too long
 */
export function isDER(h: string): boolean {
  try {
    if (!ishex(h)) return false;
    const hT = getTh(h, 0);
    const hL = getLh(h, 0);
    const iL = lenhextoint(hL);
    if (h.length == hT.length + hL.length + iL * 2) return true;
    return false;
  } catch (ex) {
    return false;
  }
}

export function hextooid(h: string): string {
  if (!ishex(h)) throw new Error(`not hex: ${h}`);
  try {
    let a: string[] = [];

    // a[0], a[1]
    let hex0 = h.substr(0, 2);
    let i0 = parseInt(hex0, 16);
    a[0] = new String(Math.floor(i0 / 40)).toString();
    a[1] = new String(i0 % 40).toString();

    // a[2]..a[n]
    let hex1 = h.substr(2);
    let b = [];
    for (let i = 0; i < hex1.length / 2; i++) {
      b.push(parseInt(hex1.substr(i * 2, 2), 16));
    }
    let c = [];
    let cbin = "";
    for (var i = 0; i < b.length; i++) {
      if (b[i] & 0x80) {
	cbin = cbin + strpad((b[i] & 0x7f).toString(2), 7);
      } else {
	cbin = cbin + strpad((b[i] & 0x7f).toString(2), 7);
	c.push(new String(parseInt(cbin, 2)));
	cbin = "";
      }
    }

    let s = a.join(".");
    if (c.length > 0) s = s + "." + c.join(".");
      return s;
  } catch (ex) {
    throw new Error(`malformed oid hex: ${h} ${ex}`);
  }
}
