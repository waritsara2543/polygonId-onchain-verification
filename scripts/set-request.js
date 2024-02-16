const { Web3 } = require("web3");
const { poseidon } = require("@iden3/js-crypto");
const { SchemaHash } = require("@iden3/js-iden3-core");
const { prepareCircuitArrayValues } = require("@0xpolygonid/js-sdk");

const Operators = {
  NOOP: 0, // No operation, skip query verification in circuit
  EQ: 1, // equal
  LT: 2, // less than
  GT: 3, // greater than
  IN: 4, // in
  NIN: 5, // not in
  NE: 6, // not equal
};

async function sha256(inputString) {
  const encoder = new TextEncoder();
  const data = encoder.encode(inputString);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashedString = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
  return hashedString;
}

// function sha256ToNumber(sha256HexString) {
//   const numericValue = BigInt("0x" + sha256HexString);
//   return numericValue.toString();
// }

function packValidatorParams(query, allowedIssuers = []) {
  let web3 = new Web3(
    Web3.givenProvider || "https://1899-115-67-227-2.ngrok-free.app"
  );
  return web3.eth.abi.encodeParameter(
    {
      CredentialAtomicQuery: {
        schema: "uint256",
        claimPathKey: "uint256",
        operator: "uint256",
        slotIndex: "uint256",
        value: "uint256[]",
        queryHash: "uint256",
        allowedIssuers: "uint256[]",
        circuitIds: "string[]",
        skipClaimRevocationCheck: "bool",
        claimPathNotExists: "uint256",
      },
    },
    {
      schema: query.schema,
      claimPathKey: query.claimPathKey,
      operator: query.operator,
      slotIndex: query.slotIndex,
      value: query.value,
      queryHash: query.queryHash,
      allowedIssuers: allowedIssuers,
      circuitIds: query.circuitIds,
      skipClaimRevocationCheck: query.skipClaimRevocationCheck,
      claimPathNotExists: query.claimPathNotExists,
    }
  );
}

function coreSchemaFromStr(schemaIntString) {
  const schemaInt = BigInt(schemaIntString);
  return SchemaHash.newSchemaHashFromInt(schemaInt);
}

function calculateQueryHash(
  values,
  schema,
  slotIndex,
  operator,
  claimPathKey,
  claimPathNotExists
) {
  const expValue = prepareCircuitArrayValues(values, 64);
  const valueHash = poseidon.spongeHashX(expValue, 6);
  const schemaHash = coreSchemaFromStr(schema);
  const quaryHash = poseidon.hash([
    schemaHash.bigInt(),
    BigInt(slotIndex),
    BigInt(operator),
    BigInt(claimPathKey),
    BigInt(claimPathNotExists),
    valueHash,
  ]);
  return quaryHash;
}

async function main() {
  // you can run https://go.dev/play/p/3id7HAhf-Wi to get schema hash and claimPathKey using YOUR schema
  // suggestion: Use your own go application with that code rather than using playground (it can give a timeout just because it’s restricted by the size of dependency package)

  const schemaBigInt = "98981143719678321901732516207705665843";

  // const type = "KYCAgeCredential";
  const type = "ZKAgeAirdrop";
  const schemaUrl = "ipfs://QmTgtAC6NzVtcAF4gqvLcmCuNWgmY3N6QTT98Gz19ZvAqW";

  // merklized path to field in the W3C credential according to JSONLD  schema e.g. birthday in the KYCAgeCredential under the url "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"
  const schemaClaimPathKey =
    "3976750094387651047767245609869486666915260282965264007849929384050616836543";

  const requestId = 1;

  const inputString = 'test';
  const inputHash = await sha256(inputString)
  console.log('inputHash: ', inputHash);
  const decimalValue = sha256ToNumber(inputHash);
  console.log('decimalValue: ', decimalValue);

  const query = {
    requestId,
    schema: schemaBigInt,
    claimPathKey: schemaClaimPathKey,
    operator: Operators.EQ,
    slotIndex: 0,
    value: [decimalValue, ...new Array(63).fill(0)], // for operators 1-3 only first value matters
    circuitIds: ["credentialAtomicQuerySigV2OnChain"],
    skipClaimRevocationCheck: false,
    claimPathNotExists: 0,
  };

  query.queryHash = calculateQueryHash(
    query.value,
    query.schema,
    query.slotIndex,
    query.operator,
    query.claimPathKey,
    query.claimPathNotExists
  ).toString();

  // add the address of the contract just deployed
  // const ERC20VerifierAddress = "0x1fcC74Cc695DB86a9a918B9159B925B067d4CD0C"
  const ERC20VerifierAddress = "0x141BeD2955eDfdEAdBb2e3F461c260131d0343f2";

  let erc20Verifier = await hre.ethers.getContractAt(
    "ERC20Verifier",
    ERC20VerifierAddress
  );

  const validatorAddress = "0x1E4a22540E293C0e5E8c33DAfd6f523889cFd878"; // sig validator
  // const validatorAddress = "0x0682fbaA2E4C478aD5d24d992069dba409766121"; // mtp validator

  const invokeRequestMetadata = {
    id: "7f38a193-0918-4a48-9fac-36adfdb8b542",
    typ: "application/iden3comm-plain-json",
    type: "https://iden3-communication.io/proofs/1.0/contract-invoke-request",
    thid: "7f38a193-0918-4a48-9fac-36adfdb8b542",
    body: {
      reason: "airdrop participation",
      transaction_data: {
        contract_address: ERC20VerifierAddress,
        method_id: "b68967e2",
        chain_id: 80001,
        network: "polygon-mumbai",
      },
      scope: [
        {
          id: query.requestId,
          circuitId: query.circuitIds[0],
          query: {
            allowedIssuers: ["*"],
            context: schemaUrl,
            credentialSubject: {
              name: {
                $eq: query.value[0],
              },
            },
            type,
          },
        },
      ],
    },
  };

  try {
    const txId = await erc20Verifier.setZKPRequest(requestId, {
      metadata: JSON.stringify(invokeRequestMetadata),
      validator: validatorAddress,
      data: packValidatorParams(query),
    });
    console.log("Request set: ", txId.hash);
  } catch (e) {
    console.log("error: ", e);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });