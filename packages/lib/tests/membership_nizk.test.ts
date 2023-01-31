import {
  MembershipProver,
  MembershipVerifier,
  Tree,
  Poseidon
} from "../src/lib";
import {
  hashPersonalMessage,
  ecsign,
  privateToAddress,
  privateToPublic
} from "@ethereumjs/util";
var EC = require("elliptic").ec;
import * as path from "path";

describe("membership prove and verify", () => {
  // Init prover
  const treeDepth = 20;

  const privKeys = ["1", "a", "bb", "ccc", "dddd", "ffff"].map(val =>
    Buffer.from(val.padStart(64, "0"), "hex")
  );

  // Sign (Use privKeys[0] for proving)
  const proverIndex = 0;
  const proverPrivKey = privKeys[proverIndex];
  let proverAddress: bigint;

  let msg = Buffer.from("harry potter");
  const msgHash = hashPersonalMessage(msg);

  const { v, r, s } = ecsign(msgHash, proverPrivKey);
  const sig = `0x${r.toString("hex")}${s.toString("hex")}${v.toString(16)}`;

  let poseidon: Poseidon;

  beforeAll(async () => {
    // Init Poseidon
    poseidon = new Poseidon();
    await poseidon.initWasm();
  });

  describe("pubkey_membership prover and verify", () => {
    const config = {
      witnessGenWasm: path.join(
        __dirname,
        "../../circuits/build/pubkey_membership/pubkey_membership_js/pubkey_membership.wasm"
      ),
      circuit: path.join(
        __dirname,
        "../../circuits/build/pubkey_membership/pubkey_membership.circuit"
      )
    };

    it("should prove and verify valid signature and merkle proof", async () => {
      const pubKeyTree = new Tree(treeDepth, poseidon);

      let proverPubKeyHash;
      // Insert the members into the tree
      for (const privKey of privKeys) {
        const pubKey = privateToPublic(privKey);
        const pubKeyHash = poseidon.hashPubKey(pubKey);
        pubKeyTree.insert(pubKeyHash);

        // Set prover's public key hash for the reference below
        if (proverPrivKey === privKey) proverPubKeyHash = pubKeyHash;
      }

      const pubKeyMembershipProver = new MembershipProver(config);

      const index = pubKeyTree.indexOf(proverPubKeyHash as bigint);
      const merkleProof = pubKeyTree.createProof(index);

      const { proof, publicInput } = await pubKeyMembershipProver.prove(
        sig,
        msgHash,
        merkleProof
      );

      const pubKeyMembershipVerifier = new MembershipVerifier({
        circuit: config.circuit
      });

      await pubKeyMembershipVerifier.initWasm();

      expect(await pubKeyMembershipVerifier.verify(proof, publicInput)).toBe(
        true
      );
    });
  });

  describe("addr_membership prover and verify", () => {
    const config = {
      witnessGenWasm: path.join(
        __dirname,
        "../../circuits/build/addr_membership/addr_membership_js/addr_membership.wasm"
      ),
      circuit: path.join(
        __dirname,
        "../../circuits/build/addr_membership/addr_membership.circuit"
      )
    };

    it("should prove and verify valid signature and merkle proof", async () => {
      const addressTree = new Tree(treeDepth, poseidon);

      let proverAddress;
      // Insert the members into the tree
      for (const privKey of privKeys) {
        const address = BigInt(
          "0x" + privateToAddress(privKey).toString("hex")
        );
        addressTree.insert(address);

        // Set prover's public key hash for the reference below
        if (proverPrivKey === privKey) proverAddress = address;
      }

      const addressMembershipProver = new MembershipProver(config);

      const index = addressTree.indexOf(proverAddress as bigint);
      const merkleProof = addressTree.createProof(index);

      const { proof, publicInput } = await addressMembershipProver.prove(
        sig,
        msgHash,
        merkleProof
      );

      const addressMembershipVerifier = new MembershipVerifier({
        circuit: config.circuit
      });

      await addressMembershipVerifier.initWasm();

      expect(await addressMembershipVerifier.verify(proof, publicInput)).toBe(
        true
      );
    });
  });
});
