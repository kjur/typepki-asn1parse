import { ishex, hexpad, hextouricmp, hextoutf8, strpad  } from "typepki-strconv";
import { OIDDataBase, OIDSET_CRYPTO, OIDSET_X509 } from "typepki-oiddb";

const oiddb = OIDDataBase.instance;
oiddb.regist([OIDSET_CRYPTO, OIDSET_X509]);

/**
 * ASN.1 parsing option
 * @description
 * Optional parameters for {@link asn1parse}
 */ 
export interface ASN1ParseOption {
  /**
   * specifies how far the depth number of ASN.1 structure will be parsed.
   */
  maxDepth?: number;
  /**
   * member "tlv" of ASN.1 TLV hexadecimal also concluded or not
   */
  withTLV?: true;
}

/**
 * parse ASN.1 hexadecimal string
 * @param h - ASN.1 hexadecimal string
 * @param opt - optional ASN.1 parsing opiton
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
export function asn1parse(
  h: string,
  opt?: ASN1ParseOption
): Record<string, any> {
  let maxDepth: number = -1;
  if (opt != undefined && "maxDepth" in opt) {
    maxDepth = opt.maxDepth as number;
  }
  const _opt = (opt != undefined) ? opt : {};
  return _asn1parse(h, 1, maxDepth, _opt);
}

function _asn1parse(
  h: string,
  currentDepth: number,
  maxDepth: number,
  opt: ASN1ParseOption
): Record<string, any> {
  let p: Record<string, any> = {};
  const hT = getTh(h, 0);
  const tag = taghextos(hT);
  const hL = getLh(h, 0);
  const iL = lenhextoint(hL);
  let value: string | Record<string, any> = getVh(h, 0);

  if (maxDepth != -1 && currentDepth >= maxDepth) {
    value = { "hex": value };
    let result: Record<string, any> = { t: tag, v: value };
    if (opt.withTLV === true) result.tlv = h;
    return result;
  }

  if (["seq", "set"].includes(tag) || tag.match(/^a\d$/)) {
    const aList = getDERTLVList(h, hT.length + hL.length, iL * 2);
    value = aList.map((hItem) => _asn1parse(hItem, currentDepth + 1, maxDepth, opt));
  }
  if (["octstr"].includes(tag) && isDER(h)) {
    try {
      value = { "asn": _asn1parse(value as string, currentDepth + 1, maxDepth, opt) };
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

  let result: Record<string, any> = { t: tag, v: value };
  if (opt.withTLV === true) result.tlv = h;
  return result;
}

function oidtoname(oid: string): string {
  return oiddb.oidtoname(oid);
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

/**
 * get ASN.1 object TLV hexadecimal string at specified string index
 * @param h - string supposed to be a ASN.1 TLV hexadecimal at specified index
 * @parma sidx - string index of ASN.1 TLV hexadecimal
 * @return ASN.1 TLV hexadecimal string
 * @example
 * getTLVh("zzz0201fazzz", 3) -> "0201fa"
 * getTLVh("zzz0202fa0czzz", 3) -> "0202fa0c"
 */
export function getTLVh(h: string, sidx: number): string {
  const hT = getTh(h, sidx);
  const hL = getLh(h, sidx);
  const hV = getVh(h, sidx);
  return `${hT}${hL}${hV}`;
}

/**
 * get ASN.1 object T(tag) hexadecimal string at specified string index
 * @param h - string supposed to be a ASN.1 TLV hexadecimal at specified index
 * @parma sidx - string index of ASN.1 TLV hexadecimal
 * @return ASN.1 T(tag) hexadecimal string
 * @example
 * getTLVh("zzz0201fazzz", 3) -> "02"
 * getTLVh("zzzzz0202fa0czzz", 5) -> "02"
 */
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

// === lenhex / int =======================================

/**
 * convert ASN.1 TLV length octet to ASN.1 length value
 * @param hL - hexadecimal string of ASN.1 length octet
 * @return ASN.1 length value. For ASN.1 BER indefinite length (i.e. "80"), returns -1
 * @see {@link inttolenhex}
 *
 * @description
 * This function converts an ASN.1 TLV length octet to ASN.1 TLV length value.
 * When the input is "80" which means ASN.1 BER indefinite length, it returns a
 * special value -1.
 *
 * @example
 * lenhextoint("10") -> 16
 * lenhextoint("81ff") -> 256
 * lenhextoint("80") -> -1 // indefinite length
 * lenhextoint("82047b") -> 1147
 */
export function lenhextoint(hL: string): number {
  if (hL === "80") return -1;
  const iL0 = Number.parseInt(hL.slice(0, 2), 16);
  if (iL0 < 128) return iL0;
  if ((iL0 & 127) !== (hL.length / 2 - 1)) {
    throw new Error(`malformed ASN.1 L octets: ${hL}`);
  }
  return Number.parseInt(hL.slice(2), 16);
}

/**
 * convert ASN.1 length value to ASN.1 TLV length octet
 * @param n - ASN.1 length value. 
 * @return an hexadecimal string of ASN.1 length octet. For ASN.1 BER indefinite length -1, returns "80"
 * @see {@link lenhextoint}
 *
 * @description
 * This function converts an ASN.1 TLV length value to an ASN.1 TLV length octet.
 * When the input is -1  which means ASN.1 BER indefinite length, it returns "80".
 *
 * @example
 * inttolenhex(16) -> "10"
 * inttolenhex(256) -> "81ff"
 * inttolenhex(-1) -> "80"
 * inttolenhex(1147) -> "82047b"
 */
export function inttolenhex(n: number): string {
  if (n == -1) return "80"; // indefinite length
  if (n < 0) throw new Error(`n shall be non negative except indefinite length: n=${n}`);
  if (n < 128) {
    const hex = n.toString(16);
    return (hex.length % 2 == 0) ? hex : `0${hex}`;
  }
  let hex = hexpad(n.toString(16));
  let numoctet = hex.length / 2;
  if (numoctet > 127) throw new Error(`too large for ASN.1 Length: num octet=${numoctet}`);
  let hHead = (128 + numoctet).toString(16);
  return `${hHead}${hex}`;
}

/**
 * get ASN.1 value octet hexadecimal string at specified ASN.1 TLV string index
 * @param h - string at specified index supposed to be ASN.1 TLV string
 * @param sidx - string index of ASN.1 TLV
 * @return ASN.1 value octet hexadecimal string
 * @example
 * getVh("zzz0203abcdef", 3) -> "abcdef"
 */
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

/**
 * convert hexadecimal ASN.1 ObjectIdentifier value to OID string
 * @param h - hexadecimal ASN.1 ObjectIdentifier value
 * @return OID string (ex. "1.2.3.4")
 * @example
 * hextooid("550406") -> "2.5.4.6"
 */
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

// == digging parsed ASN.1 ================================================

/**
 * get value from parsed ASN.1
 * @param pASN - JSON object of parsed ASN.1 structure
 * @param key - dot concatinated string of ASN.1 tag name or index of structured object
 * @param defaultValue - default return value when ASN.1 item can't be found
 * @return item identified by key. When item is not found, return defaultValue
 * @describe
 * This function will get an item refered by "key" in "pASN" which may be created
 * by the function {@link asn1parse}.
 * When the item identified by "key" isn't found, it returns undefined or "defaultValue".
 * @example
 * const parsedASN = {
 *   t: "seq",
 *   v: [
 *     {t:"int", v:"01"},
 *     {t:"seq", v:[{t:"utf8str", v:{str: "test"}}]}
 *   ]
 * };
 * dig(parsedASN, "seq.0") -> {t:"int", v:"01"}
 * dig(parsedASN, "seq.1.seq.0.utf8str") -> {str: "test"}
 * dig(parsedASN, "utctime", null) -> null // not found
 */
export function dig(pASN: Record<string, any>, key: string, defaultValue?: any): string | Record<string, any> {
  const aKey: string[] = key.split(".");
  try {
    return dig_value(pASN, aKey, defaultValue);
  } catch (ex) {
    //console.log(ex);
    return defaultValue;
  }
}

function dig_value(pASN: Record<string, any>, aKey: string[], defaultValue?: any): string | Record<string, any> | Record<string, any>[] {
  if (aKey.length == 0) return pASN;
  const key0: string | undefined = aKey.shift();
  if (key0 === undefined) return defaultValue;
  if (pASN.t !== key0) return defaultValue;
  if (dig_isstructtag(key0)) return dig_list(pASN.v, aKey, defaultValue);
  return pASN.v;
}

function dig_list(aASN: Record<string, any>[], aKey: string[], defaultValue?: any): string | Record<string, any> | Record<string, any>[] {
  if (aKey.length == 0) return aASN;
  const key0: string | undefined = aKey.shift();
  if (key0 === undefined) return defaultValue;
  try {
    const ikey0 = parseInt(key0);
    return dig_value(aASN[ikey0], aKey, defaultValue);
  } catch (ex) {
    //console.log(ex);
  }
  return defaultValue;
}

/*
function dig_istag(key: string): boolean {
  return true;
}
 */

function dig_isstructtag(key: string): boolean {
  if (["seq", "set"].includes(key)) return true;
  if (key.slice(0, 1) === "a") return true;
  return false;
}

// == canonicalizer ============
/**
 * canonicalize parsed ASN.1 ObjectIdentifier value to oid numbers
 * @param pValue - parsed ASN.1 value of ObjectIdentifier
 * @return a string of ObjectIdentifier value (ex. "1.2.3.4")
 * @see [OIDDataBase.nametooid](https://kjur.github.io/typepki-oiddb/classes/OIDDataBase.html#nametooid)
 * @example
 * asn1oidcanon({oid: "P-256"}) -> "1.2840.10045.3.1.7"
 * asn1oidcanon{{oid: "prime256v1"}) -> "1.2840.10045.3.1.7"
 * asn1oidcanon({oid: "ecPublicKey"}) -> "1.2.840.10045.2.1"
 * asn1oidcanon({oid: "1.2.3.4"}) -> "1.2.3.4"
 */
export function asn1oidcanon(pValue: Record<string, string>): string {
  if (pValue.oid.match(/^[0-9.]+$/)) return pValue.oid;
  return oiddb.nametooid(pValue.oid);
}
