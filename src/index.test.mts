import { describe, expect, test } from "bun:test";
import { asn1parse, getDERTLVList, getLh, getTLVh, getVh, getTh, hextooid, inttolenhex, isDER, lenhextoint, dig, asn1oidcanon } from "./index.mts";

test("getLh", () => {
  expect(getLh("020100", 0)).toBe("01");
  expect(getLh("02020000", 0)).toBe("02");
  expect(getLh("aa02020000", 2)).toBe("02");
  expect(getLh("028105ffff", 0)).toBe("8105");
  expect(getLh("0282053affff", 0)).toBe("82053a");
  expect(getLh("0280ffffffff", 0)).toBe("80");
  expect(() => {
    getLh("02zz0000", 0);
  }).toThrow(/t get ASN.1 L octets/);
  expect(() => {
    getLh("f", 0);
  }).toThrow(/t get ASN.1 L octets/);
  expect(getLh(SSLLE1, 618 * 2)).toBe("81f4");
});

test("lenhextoint", () => {
  expect(lenhextoint("03")).toBe(3);
  expect(lenhextoint("7f")).toBe(127);
  expect(lenhextoint("80")).toBe(-1);
  expect(lenhextoint("8185")).toBe(133);
  expect(lenhextoint("82047b")).toBe(1147);
  expect(() => {lenhextoint("8204")}).toThrow(/malformed ASN/);
  expect(() => {lenhextoint("8204567a")}).toThrow(/malformed ASN/);
});

test("inttolenhex", () => {
  expect(inttolenhex(3)).toBe("03");
  expect(inttolenhex(127)).toBe("7f");
  expect(inttolenhex(-1)).toBe("80");
  expect(inttolenhex(128)).toBe("8180");
  expect(inttolenhex(133)).toBe("8185");
  expect(inttolenhex(1147)).toBe("82047b");
  expect(() => {inttolenhex(-1234)}).toThrow(/be non negative/);
});

test("getVh", () => {
  expect(getVh("020147", 0)).toBe("47");
  expect(getVh("02024789...", 0)).toBe("4789");
  expect(getVh("...02024789...", 3)).toBe("4789");
  expect(() => {
    getVh("...02804789...", 3);
  }).toThrow(/not supported yet/);
  expect(getVh(SSLLE1, 618 * 2)).toBe(SSLLE1PARTAV);
});

test("getTLVh", () => {
  expect(getTLVh(SSLLE1, 66)).toBe("300d06092a864886f70d01010b0500"); // sigalg
});

// Let's Encrypt SSL certificate on 2024-Apr-11
const SSLLE1 =
  "3082047130820359a0030201020212044210634a03eb37e8f2b73f8bb3b2a5d374300d06092a864886f70d01010b05003032310b300906035504061302555331163014060355040a130d4c6574277320456e6372797074310b3009060355040313025233301e170d3234303431313138303234345a170d3234303731303138303234335a301431123010060355040313096c656e63722e6f72673059301306072a8648ce3d020106082a8648ce3d030107034200046707af98b7881bc6bc4dff9e1968c7ffa1f40306ac22331a1b5aa207bc538a8c9b26be9beaab93655e56e2067ecc285a0b67fc44c6c63b5004080cce05ff6d2ea382026830820264300e0603551d0f0101ff040403020780301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff04023000301d0603551d0e0416041400f35862bcf0e777f72ff1e33664c81d817ce992301f0603551d23041830168014142eb317b75856cbae500940e61faf9d8b14c2c6305506082b0601050507010104493047302106082b060105050730018615687474703a2f2f72332e6f2e6c656e63722e6f7267302206082b060105050730028616687474703a2f2f72332e692e6c656e63722e6f72672f306f0603551d110468306682096c656e63722e6f7267820f6c657473656e63727970742e636f6d820f6c657473656e63727970742e6f7267820d7777772e6c656e63722e6f726782137777772e6c657473656e63727970742e636f6d82137777772e6c657473656e63727970742e6f726730130603551d20040c300a3008060667810c01020130820106060a2b06010401d6790204020481f70481f400f200770048b0e36bdaa647340fe56a02fa9d30eb1c5201cb56dd2c81d9bbbfab39d884730000018ece8a776d0000040300483046022100935172533af70c2214efbda47ef1142ed04ff02bbfe0b481841d3cb7cdd39a07022100b50c4ee0a5ce0d87b4f562b252ad733e1e59757f048f71e41d1cdf8d1e9cfa75007700dfe156ebaa05afb59c0f86718da8c0324eae56d96ea7f5a56a01d1c13bbe525c0000018ece8a78250000040300483046022100f108ac1c257833f97d75f4019841fd58c867c48cfa02b8344d44692a6061a072022100f44f35414495b9ecaef6b6862214c123bb823c6b469363bbe69d1f0c5809c9e0300d06092a864886f70d01010b050003820101001c9bbd246c9f5e744ee07d124ceffb531439ced5453e7a9012cf75d585524be9424240e6fcb8b54fcf5fe70589f142077331bce21fe2581d88571d90a7be59c9c2e85411f62758b6e1e1b0be191be51fdae85b8a0c0b2795a6a02362da43cf5d47449c52d5edc7e9aa2fff0f539ae16ba6149b54bf27faffd3f86db3c726b0d02e392145a89c3b9a85dd4b8eb2835e66ea9bbe9325e53734416d9b535d62fa8d7167f3e0a425624faf019a327bb2b917814b4146b89b4c2a7766eadf4933c0b79579d038f37948c718771b48d50de5d01a3641ba905adf37874687fb9c5d6c0a83bec5df1a27511fac4d69a838ec21258f59789545b88ed547ce45eb942abee9";

// Let's Encrypt SSL certificate on 2024-Apr-11, extV 1.3.6.1.4.1.11129.2.4.2 ASN.1 V, sidx=618*2
const SSLLE1PARTAV =
  "00f200770048b0e36bdaa647340fe56a02fa9d30eb1c5201cb56dd2c81d9bbbfab39d884730000018ece8a776d0000040300483046022100935172533af70c2214efbda47ef1142ed04ff02bbfe0b481841d3cb7cdd39a07022100b50c4ee0a5ce0d87b4f562b252ad733e1e59757f048f71e41d1cdf8d1e9cfa75007700dfe156ebaa05afb59c0f86718da8c0324eae56d96ea7f5a56a01d1c13bbe525c0000018ece8a78250000040300483046022100f108ac1c257833f97d75f4019841fd58c867c48cfa02b8344d44692a6061a072022100f44f35414495b9ecaef6b6862214c123bb823c6b469363bbe69d1f0c5809c9e0";

test("getDERTLVList", () => {
  expect(getDERTLVList("300902010a02010b02010c", 4, 18)).toEqual(["02010a", "02010b", "02010c"]);
  expect(getDERTLVList("...300902010a02010b02010c", 7, 18)).toEqual(["02010a", "02010b", "02010c"]);
});

test("isDER", () => {
  expect(isDER("0201ff")).toBe(true);
  expect(isDER(SSLLE1)).toBe(true);
  expect(isDER("0201ffbbaa")).toBe(false);
  expect(isDER("foo")).toBe(false);
});

test("hextooid", () => {
  expect(hextooid("550406")).toBe("2.5.4.6");
});

describe("dig", () => {
  test("basic test", () => {
    expect(dig({t:"seq", v:[]}, "seq")).toEqual([]);
    expect(dig({t:"seq", v:[{t:"int", v:"0102"}]}, "seq")).toEqual([{t:"int", v:"0102"}]);
    expect(dig({t:"seq", v:[{t:"int", v:"0102"}]}, "seq.0")).toEqual({t:"int", v:"0102"});
    expect(dig({t:"seq", v:[{t:"int", v:"01"},{t:"int", v:"02"}]}, "seq.1")).toEqual({t:"int", v:"02"});
  });
  test("PKCS8 E256 private key", () => {
    const p = asn1parse(PRV8E256HEX);
    expect(dig(p, "seq.0")).toEqual({t:"int", v:"00"});
    expect(dig(p, "seq.1.seq.0.oid")).toEqual({oid: "ecPublicKey"});
    expect(dig(p, "seq.1.seq.1.oid")).toEqual({oid: "prime256v1"});
    expect(dig(p, "seq.1.seq.5.oid")).toBe(undefined);
    expect(dig(p, "int")).toBe(undefined);
  });
  test("PKCS8 E256 public key", () => {
    const p = asn1parse(PUB8E256HEX);
    expect(dig(p, "seq.0.seq.0.oid")).toEqual({oid: "ecPublicKey"});
    expect(dig(p, "seq.0.seq.1.oid")).toEqual({oid: "prime256v1"});
    expect(dig(p, "seq.1.seq.6.oid")).toBe(undefined);
    expect(dig(p, "utf8str")).toBe(undefined);
    expect(dig(p, "utf8str", null)).toBe(null);
  });
});

// rfc9500testkey/testecp256.prv.p8p.der > hex
const PRV8E256HEX = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420e6cb5bdd80aa45ae9c95e8c15476679ffec953c16851e711e743939589c64fc1a14403420004422548f88fb782ffb5eca3744452c72a1e558fbd6f73be5e48e93232cc45c5b16c4cd10c4cb8d5b8a17139e94882c8992572993425f41419ab7e90a42a494272";

// rfc9500testkey/testecp256.pub.p8.der > hex
const PUB8E256HEX = "3059301306072a8648ce3d020106082a8648ce3d03010703420004422548f88fb782ffb5eca3744452c72a1e558fbd6f73be5e48e93232cc45c5b16c4cd10c4cb8d5b8a17139e94882c8992572993425f41419ab7e90a42a494272";

test("asn1oidcanon", () => {
  expect(asn1oidcanon({oid: "P-256"})).toBe("1.2.840.10045.3.1.7");
  expect(asn1oidcanon({oid: "prime256v1"})).toBe("1.2.840.10045.3.1.7");
  expect(asn1oidcanon({oid: "P-384"})).toBe("1.3.132.0.34");
  expect(asn1oidcanon({oid: "secp384r1"})).toBe("1.3.132.0.34");
  expect(asn1oidcanon({oid: "P-521"})).toBe("1.3.132.0.35");
  expect(asn1oidcanon({oid: "secp521r1"})).toBe("1.3.132.0.35");
  expect(asn1oidcanon({oid: "ecPublicKey"})).toBe("1.2.840.10045.2.1");
  expect(asn1oidcanon({oid: "1.2.3.4"})).toBe("1.2.3.4");
});

test("asn1parse string primitives", () => {
  expect(asn1parse("0c0431323334")).toEqual({t:"utf8str", v:{str:"1234"}});
  expect(asn1parse("120431323334")).toEqual({t:"numstr", v:{str:"1234"}});
  expect(asn1parse("130431323334")).toEqual({t:"prnstr", v:{str:"1234"}});
  expect(asn1parse("160431323334")).toEqual({t:"ia5str", v:{str:"1234"}});
  expect(asn1parse("1a0431323334")).toEqual({t:"visstr", v:{str:"1234"}});
  expect(asn1parse("1c0431323334")).toEqual({t:"unistr", v:{str:"1234"}});
  expect(asn1parse("13025553")).toEqual({t:"prnstr",v:{str:"US"}});
});

test("asn1parse", () => {
  expect(asn1parse("020101")).toEqual({t:"int",v:"01"});
  expect(asn1parse("06092a864886f70d01010b")).toEqual({t:"oid",v:{oid:"sha256WithRSAEncryption"}});
  expect(asn1parse("170d3234303431313138303234345a")).toEqual({t:"utctime",v:"240411180244Z"});
  expect(asn1parse("300902010a02010b02010c")).toEqual({
    t: "seq",
    v: [
      { t: "int", v: "0a" },
      { t: "int", v: "0b" },
      { t: "int", v: "0c" }
    ]
  });
  //expect(asn1parse(SSLLE1)).toEqual({t:"seq",v:"01"});
  //expect(asn1parse("3081dc020101044201d924dcca0a887f8d99767a37d874e637a12ccb477d6e08665356694d68b7655e5069638fde7b45c854013dc77a35b18655b84c966a60220d40f91ed9f5145802eaa00706052b81040023a18189038186000401d0fd7257a84c747f562575c07385dbebf2f52bea58083db82fdd1531d8aae3cc875ff02ff7fa2da260d8eb62d6d2f5d649278e321736a0628cbbb30308b6e618db00f62ad204c6460359bc818ab8961bf0f0fc0ec5aae8a428173ce56f00de9b157c1e5c82c64f562fcadefc4a4c28f6d342cf3ef616fc82d33b7285c921f2bf36fdd8")).toEqual({t:"seq",v:"01"});
});

describe("asn1parse explicit depth", () => {
  test("depth = -1", () => {
    expect(asn1parse("300d300602010a02010b310302010c", { maxDepth: -1 })).toEqual({
      t: "seq",
      v: [{
        t: "seq",
        v: [{t:"int", v:"0a"},{t:"int", v:"0b"}]
      },{
        t: "set",
        v: [{t:"int", v:"0c"}]
      }]
    });
  });
  test("depth = 1", () => {
    expect(asn1parse("300d300602010a02010b310302010c", { maxDepth: 1 })).toEqual({
      t: "seq",
      v: { hex: "300602010a02010b310302010c" }
    });
  });
  test("depth = 2", () => {
    expect(asn1parse("300d300602010a02010b310302010c", { maxDepth: 2 })).toEqual({
      t: "seq",
      v: [
        { t: "seq", v: { hex: "02010a02010b"} },
        { t: "set", v: { hex: "02010c" } }
      ]
    });
  });
});

describe("asn1parse withTLV", () => {
  test("020101", () => {
    expect(asn1parse("020101", { withTLV: true })).toEqual({t:"int",v:"01",tlv:"020101"});
  });
  test("depth = 2", () => {
    expect(asn1parse("300d300602010a02010b310302010c", { maxDepth: 2, withTLV: true })).toEqual({
      t: "seq",
      v: [
        { t: "seq", v: { hex: "02010a02010b"}, tlv: "300602010a02010b" },
        { t: "set", v: { hex: "02010c" }, tlv: "310302010c" }
      ],
      tlv: "300d300602010a02010b310302010c",
    });
  });
});

describe("asn1parse RSAPSS AlgorithmIdentifier", () => {
  test("rsaPSS 256 256 32", () => {
    expect(asn1parse(hAlgIdPSS256)).toEqual(pAlgIdPSS256);
  });
  test("rsaPSS 512 512 64", () => {
    expect(asn1parse(hAlgIdPSS512)).toEqual(pAlgIdPSS512);
  });
});

// AlgorithmIdentifier rsaPSS hash=sha256, mgf1=sha256, salt=32
const hAlgIdPSS256 = "304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120";
const pAlgIdPSS256 = {
  t: "seq",
  v: [{
    t: "oid", v: { oid: "rsaPSS" }
  },{
    t: "seq",
    v: [{
      t: "a0",
      v: [{
        t: "seq",
        v: [
          { t: "oid", v: { "oid": "sha256" } },
          { t: "null", v: "" },
        ]
      }]
    },{
      t: "a1",
      v: [{
        t: "seq",
        v: [{
          t: "oid", v: { oid: "mgf1" }
        },{
          t: "seq",
          v: [
            { t: "oid", v: { "oid": "sha256" } },
            { t: "null", v: "" }
          ]
        }]
      }]
    },{
      t: "a2",
      v: [{ t: "int", v: "20" }]
    }]
  }]
};

// AlgorithmIdentifier rsaPSS hash=sha512, mgf1=sha512, salt=64
const hAlgIdPSS512 = "304106092a864886f70d01010a3034a00f300d06096086480165030402030500a11c301a06092a864886f70d010108300d06096086480165030402030500a203020140";
const pAlgIdPSS512 = {
  t: "seq",
  v: [{
    t: "oid", v: { oid: "rsaPSS" }
  },{
    t: "seq",
    v: [{
      t: "a0",
      v: [{
        t: "seq",
        v: [
          { t: "oid", v: { "oid": "sha512" } },
          { t: "null", v: "" },
        ]
      }]
    },{
      t: "a1",
      v: [{
        t: "seq",
        v: [{
          t: "oid", v: { oid: "mgf1" }
        },{
          t: "seq",
          v: [
            { t: "oid", v: { "oid": "sha512" } },
            { t: "null", v: "" }
          ]
        }]
      }]
    },{
      t: "a2",
      v: [{ t: "int", v: "40" }]
    }]
  }]
};
/*
SEQUENCE
  ObjectIdentifier rsaPSS (1 2 840 113549 1 1 10)
  SEQUENCE
    [0]
      SEQUENCE
        ObjectIdentifier sha512 (2 16 840 1 101 3 4 2 3)
        NULL
    [1]
      SEQUENCE
        ObjectIdentifier pkcs1-MGF (1 2 840 113549 1 1 8)
        SEQUENCE
          ObjectIdentifier sha512 (2 16 840 1 101 3 4 2 3)
          NULL
    [2]
      INTEGER 40
 */
