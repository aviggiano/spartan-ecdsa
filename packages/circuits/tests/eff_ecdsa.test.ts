const wasm_tester = require("circom_tester").wasm;
var EC = require("elliptic").ec;
import * as path from "path";
import { getEffEcdsaCircuitInput } from "./test_utils";
import * as fs from "fs/promises";
import { mutators } from "circom-mutator";

const ec = new EC("secp256k1");

describe("ecdsa", () => {
  it("should verify valid message", async () => {
    const circuit = await wasm_tester(
      path.join(__dirname, "./circuits/eff_ecdsa_test.circom"),
      {
        prime: "secq256k1"
      }
    );

    const privKey = Buffer.from(
      "f5b552f608f5b552f608f5b552f6082ff5b552f608f5b552f608f5b552f6082f",
      "hex"
    );
    const pubKey = ec.keyFromPrivate(privKey.toString("hex")).getPublic();
    const msg = Buffer.from("hello world");
    const circuitInput = getEffEcdsaCircuitInput(privKey, msg);

    const w = await circuit.calculateWitness(circuitInput, true);

    await circuit.assertOut(w, {
      pubKeyX: pubKey.x.toString(),
      pubKeyY: pubKey.y.toString()
    });

    await circuit.checkConstraints(w);
  });

  // TODO - add more tests
});

describe("ecdsa mutation tests", () => {
  it.only("should verify valid message only on non-mutated circuit", async () => {
    const circuit = await fs.readFile(
      path.join(__dirname, "./circuits/eff_ecdsa_test.circom"),
      "utf-8"
    );
    await fs.mkdir(path.join(__dirname, "./circuits/mutated"), {
      recursive: true
    });
    mutators.forEach(mutator => {
      const mutants = mutator.mutate(circuit);
      if (mutator.id === "Secp256k1Add") {
        expect(mutants.length).toBeGreaterThan(0);
      }
      mutants.forEach(async (mutant, j) => {
        await fs.writeFile(
          `./circuits/mutated/${mutator.id}-${j}.circom`,
          mutant
        );

        const mutatedCircuit = await wasm_tester(
          path.join(__dirname, `./circuits/mutated/${mutator.id}-${j}.circom`),
          {
            prime: "secq256k1"
          }
        );

        const privKey = Buffer.from(
          "f5b552f608f5b552f608f5b552f6082ff5b552f608f5b552f608f5b552f6082f",
          "hex"
        );
        const pubKey = ec.keyFromPrivate(privKey.toString("hex")).getPublic();
        const msg = Buffer.from("hello world");
        const circuitInput = getEffEcdsaCircuitInput(privKey, msg);

        const w = await mutatedCircuit.calculateWitness(circuitInput, true);

        await mutatedCircuit.assertOut(w, {
          pubKeyX: pubKey.x.toString(),
          pubKeyY: pubKey.y.toString()
        });

        console.log("here");
        expect(await mutatedCircuit.checkConstraints(w)).toThrow();
      });
    });
  });
});
