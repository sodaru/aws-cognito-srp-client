import bigInt, { BigInteger } from "./bigInteger";
import {
  computehkdf,
  hash,
  hexHash,
  padHex,
  randomValue,
  computeSignature
} from "./cryptoUtils";
import encBase64 from "crypto-js/enc-base64";
import encHex from "crypto-js/enc-hex";
import encUtf8 from "crypto-js/enc-utf8";

const initN =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
  "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
  "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
  "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
  "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
  "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
  "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
  "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
  "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
  "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

class Srp {
  private readonly g: BigInteger = bigInt("2", 16);
  private readonly N: BigInteger = bigInt(initN, 16);
  private readonly k: BigInteger = bigInt(
    hexHash(padHex(this.N) + padHex(this.g)),
    16
  );
  private readonly poolName: string;

  private a: BigInteger;
  private A: BigInteger;

  constructor(poolId: string) {
    this.poolName = poolId.split("_")[1];
  }

  getA(): string {
    this.a = randomValue(128);
    this.A = this.g.modPow(this.a, this.N);
    if (this.A.mod(this.N).isZero()) {
      new Error("Illegal paramater. A mod N cannot be 0.");
    }
    return this.A.toString(16);
  }

  getSignature(
    username: string,
    strB: string,
    strSalt: string,
    secretBlock: string,
    password: string
  ): { timestamp: string; signature: string } {
    const B = bigInt(strB, 16);
    if (B.mod(this.N).isZero()) {
      new Error("Illegal paramater. B mod N cannot be 0.");
    }
    const salt = bigInt(strSalt, 16);

    const U = bigInt(hexHash(padHex(this.A) + padHex(B)), 16);
    if (U.isZero()) {
      throw new Error("U cannot be zero.");
    }

    const usernamePasswordHash = hash(
      encUtf8.parse(this.poolName + username + ":" + password)
    );

    const x = bigInt(hexHash(padHex(salt) + usernamePasswordHash), 16);

    const S = B.subtract(this.k.multiply(this.g.modPow(x, this.N))).modPow(
      this.a.add(U.multiply(x)),
      this.N
    );

    const paddedS = padHex(S);

    const hkdf = computehkdf(encHex.parse(paddedS), encHex.parse(padHex(U)));

    const timestamp = getNowString();

    const message = encUtf8
      .parse(this.poolName)
      .concat(encUtf8.parse(username))
      .concat(encBase64.parse(secretBlock))
      .concat(encUtf8.parse(timestamp));

    const signature = computeSignature(message, hkdf);

    return { timestamp, signature };
  }
}

export default Srp;

const getNowString = () => {
  const now = new Date();

  const monthNames = [
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec"
  ];
  const weekNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

  const weekDay = weekNames[now.getUTCDay()];
  const month = monthNames[now.getUTCMonth()];
  const day = now.getUTCDate();

  let hours: string | number = now.getUTCHours();
  if (hours < 10) {
    hours = `0${hours}`;
  }

  let minutes: string | number = now.getUTCMinutes();
  if (minutes < 10) {
    minutes = `0${minutes}`;
  }

  let seconds: string | number = now.getUTCSeconds();
  if (seconds < 10) {
    seconds = `0${seconds}`;
  }

  const year = now.getUTCFullYear();

  // ddd MMM D HH:mm:ss UTC YYYY
  const dateNow = `${weekDay} ${month} ${day} ${hours}:${minutes}:${seconds} UTC ${year}`;

  return dateNow;
};
