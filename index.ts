import { Buffer, Avalanche } from "avalanche";
import { KeyPair } from "avalanche/dist/apis/avm";
import { getPreferredHRP } from "avalanche/dist/utils";
import BinTools from "avalanche/dist/utils/bintools";
import createHash from "create-hash";

let ip: string = "192.168.10.11";
let port: number = 9650;
let protocol: string = "http";
let rpc_thread: string = "ext/bc/subnav/rpc";
let network_id: number = 5;
let chain_id: string = "X";
let bintools: BinTools = BinTools.getInstance();
let ava: Avalanche = new Avalanche(ip, port, protocol, network_id, chain_id);

function digestMessage(msgStr: string) {
  let mBuf = Buffer.from(msgStr, "utf8");
  let msgSize = Buffer.alloc(4);
  msgSize.writeUInt32BE(mBuf.length, 0);
  let msgBuf = Buffer.from(
    `\x1AAvalanche Signed Message:\n${msgSize}${msgStr}`,
    "utf8"
  );
  return createHash("sha256").update(msgBuf).digest();
}

function verify(msgStr: string, signature: string) {
  let digest = digestMessage(msgStr);
  let digestBuff = Buffer.from(digest.toString("hex"), "hex");
  let networkId = ava.getNetworkID();
  let hrp = getPreferredHRP(networkId);
  let keypair = new KeyPair(hrp, "X");
  let signedBuff = bintools.cb58Decode(signature);
  let pubKey = keypair.recover(digestBuff, signedBuff);
  let addressBuff = keypair.addressFromPublicKey(pubKey);
  let addressX = bintools.addressToString(hrp, "X", addressBuff);
  let addressP = bintools.addressToString(hrp, "P", addressBuff);

  console.log(addressP);
}

verify(process.argv[2], process.argv[3]);
