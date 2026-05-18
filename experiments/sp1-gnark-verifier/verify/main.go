package main

import (
	"fmt"
	"os"

	bn254groth16 "github.com/consensys/gnark/backend/groth16/bn254"

	"sp1-gnark-verifier/parse"
)

const fixturesDir = "../sp1-hello-world/fixtures"

func main() {
	vk, err := parse.LoadVK(fixturesDir + "/vk.bin")
	die("load vk", err)

	proof, err := parse.LoadSeal(fixturesDir + "/seal.bin")
	die("load seal", err)

	pubInputs, err := parse.LoadPublicInputs(fixturesDir + "/public_inputs.json")
	die("load public inputs", err)

	if err := bn254groth16.Verify(proof, vk, pubInputs); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS")
}

func die(msg string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %s: %v\n", msg, err)
		os.Exit(1)
	}
}
