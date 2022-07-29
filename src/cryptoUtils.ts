import bigInt, { BigInteger } from "./bigInteger";
import sha256 from "crypto-js/sha256";
import hmacSha256 from "crypto-js/hmac-sha256";
import encBase64 from "crypto-js/enc-base64";
import encHex from "crypto-js/enc-hex";
import encUtf8 from "crypto-js/enc-utf8";
import WordArray from "crypto-js/lib-typedarrays";

const polyFillCrypto = (): Crypto => {
  // Native crypto from window (Browser)
  if (typeof window !== "undefined" && window.crypto) {
    return window.crypto;
  }

  // Native (experimental IE 11) crypto from window (Browser)
  // @ts-expect-error window in IE11 contains msCrypto
  if (typeof window !== "undefined" && window.msCrypto) {
    // @ts-expect-error window in IE11 contains msCrypto
    return window.msCrypto;
  }

  // @ts-expect-error require is present in node env
  if (typeof require === "function") {
    // @ts-expect-error require is present in node env
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require("crypto").webcrypto;
  }
};

const crypto = polyFillCrypto();

export const padHex = (bigInteger: BigInteger) => {
  let hashStr = bigInteger.toString(16);
  if (hashStr.length % 2 === 1) {
    hashStr = `0${hashStr}`;
  } else if ("89ABCDEFabcdef".indexOf(hashStr[0]) !== -1) {
    hashStr = `00${hashStr}`;
  }
  return hashStr;
};

export const hash = (str: WordArray) => {
  const hashHex = sha256(str).toString();

  return new Array(64 - hashHex.length).join("0") + hashHex;
};

export const hexHash = (hexStr: string) => {
  return hash(encHex.parse(hexStr));
};

const getRandomIntFromNativeCrypto = (): number => {
  if (crypto) {
    // Use getRandomValues method (Browser)
    if (typeof crypto.getRandomValues === "function") {
      try {
        return crypto.getRandomValues(new Uint32Array(1))[0];
      } catch (err) {
        // dont do anything here
      }
    }

    // Use randomBytes method (NodeJS)
    //@ts-expect-error nativeCrypto in NodeJs has randomBytes
    if (typeof crypto.randomBytes === "function") {
      try {
        //@ts-expect-error nativeCrypto in NodeJs has randomBytes
        return crypto.randomBytes(4).readInt32LE();
      } catch (err) {
        // dont do anything here
      }
    }
  }

  throw new Error(
    "Native crypto module could not be used to get secure random number."
  );
};

export const randomValue = (nBytes: number) => {
  const words = [];

  for (let i = 0; i < nBytes; i += 4) {
    words.push(getRandomIntFromNativeCrypto());
  }

  // Convert
  const hexChars = [];
  for (let i = 0; i < nBytes; i++) {
    const bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    hexChars.push((bite >>> 4).toString(16));
    hexChars.push((bite & 0x0f).toString(16));
  }

  const hexRandom = hexChars.join("");

  const randomInt = bigInt(hexRandom, 16);

  return randomInt;
};

export const computehkdf = (ikm: WordArray, salt: WordArray): WordArray => {
  const infoBits = encUtf8
    .parse("Caldera Derived Key")
    .concat(encUtf8.parse(String.fromCharCode(1)));

  const prk = hmacSha256(ikm, salt);
  const hmac = hmacSha256(infoBits, prk);
  return encHex.parse(hmac.toString().slice(0, 32));
};

export const computeSignature = (
  message: WordArray,
  key: WordArray
): string => {
  return encBase64.stringify(hmacSha256(message, key));
};
