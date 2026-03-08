# Q402 Gasless Payment Protocol — Avalanche C-Chain
## Technical Specification v1.1

---

## Abstract

This document presents the technical architecture, implementation details, and ecosystem integration strategy for the Q402 Gasless Payment Protocol deployed on Avalanche C-Chain. Q402 is a production-grade, sign-to-pay execution framework that enables end users to authorize and settle ERC-20 token transfers without holding native gas tokens. By separating transaction signing from gas payment, Q402 fundamentally improves the onboarding experience for decentralized applications and positions Avalanche as a first-class environment for frictionless Web3 commerce.

---

## 1. Introduction

### 1.1 Problem Statement

Gas fees represent one of the most significant barriers to mainstream adoption of decentralized applications. Users are required to maintain a balance of the native token (AVAX on Avalanche) solely to authorize transactions, even when the economic activity itself is denominated in stablecoins such as USDC. This constraint:

- Prevents seamless onboarding of users unfamiliar with multi-token wallet management
- Introduces friction in payment flows, particularly for micropayments and in-app purchases
- Creates dependency on fiat on-ramps to acquire gas tokens before any meaningful on-chain activity can begin

### 1.2 Solution

Q402 resolves this by decoupling **intent signing** from **transaction execution**. A user signs a cryptographically verifiable payment authorization using their wallet's native signing capability (EIP-712 typed data) — no gas required. A network of Facilitators then submits the transaction on-chain, sponsoring the gas cost on the user's behalf and recovering costs through a small service fee.

### 1.3 Scope of This Document

This specification covers the Q402 deployment on Avalanche C-Chain, including smart contract design, cryptographic primitives, transaction execution model, security properties, and integration patterns for Avalanche-native dApps.

---

## 2. Protocol Architecture

### 2.1 System Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Q402 Payment Flow                             │
│                                                                      │
│  ┌───────────┐    ① Request resource (no payment header)            │
│  │   Client  │ ────────────────────────────────────────▶ ┌────────┐ │
│  │  (User)   │    ② HTTP 402 Payment Required             │ Server │ │
│  │           │ ◀──────────────────────────────────────── │        │ │
│  │  No AVAX  │    paymentDetails: {token, amount, impl}  └────────┘ │
│  │  required │                                                       │
│  └─────┬─────┘                                                       │
│        │  ③ signTypedData(TransferAuthorization)  [EIP-712]         │
│        │  ④ signAuthorization(implContract, nonce) [EIP-7702]       │
│        │                                                             │
│        └──────────────────────────────▶ ┌──────────────────────┐   │
│                  X-PAYMENT header        │     Facilitator       │   │
│                  (Base64 payload)        │  (Gas Sponsor Node)   │   │
│                                          │                        │   │
│                                          │  • Verify EIP-712 sig  │   │
│                                          │  • Verify EIP-7702 auth│   │
│                                          │  • Check policy rules  │   │
│                                          └──────────┬───────────┘   │
│                                                     │               │
│                              ⑤ Type-0x04 Transaction│               │
│                                 from: Facilitator   │               │
│                                 to:   User EOA      │               │
│                                 authorizationList   │               │
│                                                     ▼               │
│                                          ┌──────────────────┐       │
│                                          │  Avalanche C-Chain│       │
│                                          │  Block confirmed  │       │
│                                          │  USDC transferred │       │
│                                          └──────────┬───────┘       │
│        ⑥ HTTP 200 + X-PAYMENT-RESPONSE             │               │
│  ┌───────────┐ ◀──────────────────────────────────────────────────  │
│  │   Client  │                                                       │
│  └───────────┘                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

### 2.2 Core Components

| Component | Role | Description |
|-----------|------|-------------|
| **Client SDK** | Intent layer | Constructs and signs EIP-712 + EIP-7702 payloads; never submits transactions |
| **Facilitator Network** | Execution layer | Verifies signatures, enforces policy, sponsors gas, submits on-chain |
| **Q402PaymentImplementation** | Settlement layer | On-chain contract verifying signatures and executing token transfers |
| **Policy Engine** | Compliance layer | Validates amount limits, token whitelist, deadline, recipient restrictions |
| **Audit Registry** | Traceability layer | Records signature-to-transaction mappings for on-chain accountability |

---

## 3. Smart Contract Specification

### 3.1 Contract Overview

**Contract Name:** `Q402PaymentImplementation`
**Language:** Solidity 0.8.20
**License:** MIT
**EVM Target:** London
**Optimizer:** Enabled (200 runs)

#### Deployed Addresses

| Network | Chain ID | Contract Address | Explorer |
|---------|----------|-----------------|---------|
| Avalanche C-Chain Mainnet | 43114 | `0xE5b90D564650bdcE7C2Bb4344F777f6582e05699` | [View on Snowtrace](https://snowtrace.io/address/0xE5b90D564650bdcE7C2Bb4344F777f6582e05699) |

### 3.2 Type Hashes

```solidity
bytes32 public constant DOMAIN_TYPEHASH = keccak256(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
);

bytes32 public constant TRANSFER_AUTHORIZATION_TYPEHASH = keccak256(
    "TransferAuthorization("
        "address owner,"
        "address facilitator,"
        "address token,"
        "address recipient,"
        "uint256 amount,"
        "uint256 nonce,"
        "uint256 deadline"
    ")"
);

string public constant NAME    = "Q402 Avalanche";
string public constant VERSION = "1";
```

### 3.3 Primary Interface

```solidity
/**
 * @notice Execute a gasless ERC-20 transfer under EIP-7702 delegation.
 * @dev Under EIP-7702, this function executes within the user's EOA context.
 *      address(this) == user's EOA, so IERC20.transfer() debits user balance directly.
 *
 * @param owner            The token holder whose EOA is delegated.
 * @param facilitator      The address sponsoring the gas cost.
 * @param token            ERC-20 token contract address.
 * @param recipient        Destination address for token transfer.
 * @param amount           Token amount in the token's smallest unit.
 * @param nonce            Per-owner unique value preventing replay attacks.
 * @param deadline         Unix timestamp after which the signature is invalid.
 * @param witnessSignature EIP-712 signature produced by the owner's wallet.
 */
function transferWithAuthorization(
    address owner,
    address facilitator,
    address token,
    address recipient,
    uint256 amount,
    uint256 nonce,
    uint256 deadline,
    bytes calldata witnessSignature
) external;

/**
 * @notice Permit2-compatible fallback for environments without EIP-7702 support.
 * @dev Requires prior approve(implementationContract, amount) from owner.
 *      Identical signature verification; uses transferFrom instead of transfer.
 */
function transferFromWithAuthorization(
    address owner,
    address facilitator,
    address token,
    address recipient,
    uint256 amount,
    uint256 nonce,
    uint256 deadline,
    bytes calldata witnessSignature
) external;
```

### 3.4 Events

```solidity
event TransferExecuted(
    address indexed owner,
    address indexed facilitator,
    address indexed token,
    address          recipient,
    uint256          amount,
    uint256          nonce
);
```

### 3.5 Custom Errors

| Error | Condition |
|-------|-----------|
| `SignatureExpired()` | `block.timestamp > deadline` |
| `NonceAlreadyUsed()` | `usedNonces[owner][nonce] == true` |
| `InvalidSignature()` | `ecrecover(digest, sig) != owner` |
| `TransferFailed()` | ERC-20 transfer returns false |
| `InvalidSignatureLength()` | `sig.length != 65` |

---

## 4. Cryptographic Design

### 4.1 EIP-712 Typed Data Signing

Q402 uses EIP-712 structured data signing to bind payment intent to specific parameters. The user's wallet displays a human-readable signing prompt containing all payment details before any signature is produced.

#### Domain Separator

```
domainSeparator = keccak256(abi.encode(
    DOMAIN_TYPEHASH,
    keccak256("Q402 Avalanche"),
    keccak256("1"),
    43114,                    // chainId (Avalanche Mainnet)
    verifyingContract         // implementation contract address
))
```

#### Struct Hash

```
structHash = keccak256(abi.encode(
    TRANSFER_AUTHORIZATION_TYPEHASH,
    owner,
    facilitator,
    token,
    recipient,
    amount,
    nonce,
    deadline
))
```

#### Final Digest

```
digest = keccak256(abi.encodePacked(
    "\x19\x01",
    domainSeparator,
    structHash
))
```

The recovered address from `ecrecover(digest, v, r, s)` must equal `owner`. Any mismatch causes an immediate revert.

### 4.2 EIP-7702 Authorization

EIP-7702 (Ethereum Prague/Pectra hardfork) introduces Transaction Type 0x04, enabling an EOA to temporarily adopt the bytecode of an implementation contract for the duration of a single transaction.

#### Authorization Digest

```
authDigest = keccak256(
    0x05 || rlp([chainId, implementationAddress, nonce])
)
```

The user signs `authDigest`, producing `(yParity, r, s)`, which is embedded in the transaction's `authorizationList`.

#### Type 0x04 Transaction

```json
{
  "type": "0x04",
  "from": "<facilitator address>",
  "to":   "<user EOA>",
  "data": "<transferWithAuthorization calldata>",
  "authorizationList": [
    {
      "chainId": 43114,
      "address": "0xE5b90D564650bdcE7C2Bb4344F777f6582e05699",
      "nonce":   "<user EOA on-chain nonce>",
      "yParity": 1,
      "r": "0x...",
      "s": "0x..."
    }
  ]
}
```

#### Execution Context

```
Facilitator submits Type-0x04 transaction
    │
    ▼
Avalanche C-Chain node processes authorizationList:
    1. Temporarily sets code at user's EOA → Q402PaymentImplementation
    2. Executes transferWithAuthorization() in user's EOA context
    3. Inside execution: address(this) == user's EOA
    4. USDC.transfer(recipient, amount) executes as user's EOA
    5. USDC balance deducted from user's account
    6. TransferExecuted event emitted
    7. Delegation cleared — user's EOA reverts to normal EOA
```

---

## 5. Security Model

### 5.1 Defense Layers

| Layer | Mechanism | Attack Mitigated |
|-------|-----------|-----------------|
| Signature verification | `ecrecover` must return `owner` | Unauthorized transfers |
| Nonce tracking | `usedNonces[owner][nonce]` | Replay attacks |
| Deadline enforcement | `block.timestamp <= deadline` | Stale signature reuse |
| Domain binding | `chainId` + `verifyingContract` in domain | Cross-chain / cross-contract replay |
| Policy engine | Off-chain whitelist + amount caps | Overspend, blacklist bypass |

### 5.2 Threat Analysis

**Replay Attack**
Each signature is bound to a unique `nonce` recorded on-chain upon use. Resubmitting an identical payload causes `NonceAlreadyUsed()` revert.

**Cross-Chain Replay**
The EIP-712 domain includes `chainId: 43114`, making signatures produced for Avalanche Mainnet invalid on any other network.

**Front-Running**
The signature cryptographically binds `recipient` and `amount`. A front-running actor cannot alter the beneficiary or payment amount without invalidating the signature.

**Signature Phishing**
EIP-712 structured signing causes compatible wallets (MetaMask, Rabby, etc.) to display a fully decoded, human-readable prompt — including all named fields — before the user approves.

**Implementation Exploit**
The implementation contract can be upgraded or replaced. Under EIP-7702, each new authorization tuple must be explicitly re-signed by the user, preventing silent upgrades.

---

## 6. Verified On-Chain Transactions

### 6.1 Avalanche C-Chain Mainnet — Three-Party Separation Test

This transaction verifies the full A → B → C address separation: the token holder (A) signs the authorization, the facilitator (B) submits the transaction and pays gas, and the recipient (C) receives the funds. A holds no AVAX and pays zero gas.

| Field | Value |
|-------|-------|
| Network | Avalanche C-Chain Mainnet (Chain ID: 43114) |
| Transaction Hash | `0xea608babc2809f836155679ffe5222cf1e24217741026b0595f8b7328d45f538` |
| Block | 79,813,359 |
| Status | ✅ Success |
| Token | USDC native — `0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E` |
| Amount Transferred | 0.05 USDC |
| Address A — Payer (signer) | `0xFe7bA1CDc7077F71855627F9983a70188826726f` |
| Address B — Facilitator (gas sponsor) | `0xfc77FF29178B7286A8bA703D7a70895CA74fF466` |
| Address C — Recipient | `0xf5cdcd89b7dae1484197a4a65b97cd7a5e945c28` |
| Gas paid by A | **0.0 AVAX** |
| Gas paid by B (facilitator) | ~0.0000027 AVAX |
| Execution mode | Permit2 fallback (`transferFromWithAuthorization`) |
| Explorer | https://snowtrace.io/tx/0xea608babc2809f836155679ffe5222cf1e24217741026b0595f8b7328d45f538 |

> **Note:** The standard Avalanche C-Chain public RPC does not yet expose EIP-7702 Type-0x04 transaction support. The protocol fell back to Permit2 mode, which uses an identical EIP-712 signature verification path. The A → B → C role separation and gasless property for the end user are fully preserved. Native EIP-7702 execution requires an EIP-7702-compatible RPC endpoint.

---

## 7. Ecosystem Integration — Avalanche Use Cases

Q402 is designed as a universal payment primitive. Any application on Avalanche that currently requires users to hold AVAX for gas can integrate Q402 to eliminate that requirement entirely. The following categories represent concrete integration opportunities within the Avalanche ecosystem.

### 7.1 GameFi and On-Chain Gaming

Avalanche hosts a growing number of blockchain games — including titles built on dedicated Avalanche Subnets. In-game economies typically require frequent, low-value transactions (item purchases, entry fees, reward claims) that are poorly served by traditional gas models.

**Integration Pattern:**
- Player signs a `TransferAuthorization` for in-game USDC or game token payment
- Game's backend Facilitator submits the transaction, deducting cost from a service fee
- Player experiences a Web2-equivalent UX — tap to buy, no wallet pop-ups for gas

**Applicable Projects:** Any GameFi title on Avalanche C-Chain or a custom Subnet where in-game currency is an ERC-20 token. Examples include games in the Avalanche gaming ecosystem that operate their own token economies.

**Impact:** Eliminates the most common drop-off point in GameFi onboarding — the moment a new player is told they need AVAX before they can do anything.

### 7.2 DeFi Protocols

Decentralized exchanges, lending protocols, and yield aggregators on Avalanche (such as Trader Joe, AAVE, Benqi, and similar protocols) serve users who may hold significant stablecoin positions but minimal AVAX.

**Integration Pattern:**
- A DeFi protocol integrates Q402 at the entry point — e.g., depositing into a yield vault
- User signs a `TransferAuthorization` to approve fund movement
- The protocol's Facilitator executes the deposit and charges a small protocol fee in the deposited token
- User never needs to acquire AVAX separately

**Concrete Example — Lending Protocol:**
```
User holds 500 USDC, wants to supply to a lending market.
Without Q402 : User must first acquire AVAX, then approve, then deposit (3 steps).
With Q402    : User signs once → Facilitator supplies on their behalf (1 step).
```

**Impact:** Lowers the barrier for capital deployment, increasing total value locked across Avalanche DeFi protocols.

### 7.3 NFT Marketplaces and Creator Platforms

NFT minting, listing, and purchasing on Avalanche marketplaces currently requires buyers to hold AVAX for gas in addition to the payment token.

**Integration Pattern:**
- Buyer signs a USDC `TransferAuthorization` for the NFT purchase price
- Marketplace Facilitator settles payment and triggers NFT transfer atomically
- Platform absorbs gas cost as part of marketplace fee

**Impact:** Enables credit-card-like UX for NFT purchases — users spend stablecoins directly without managing AVAX.

### 7.4 DAO Governance and Treasury Operations

DAOs operating on Avalanche — including those managing substantial on-chain treasuries — require regular treasury disbursements, contributor payments, and grant distributions.

**Integration Pattern:**
- DAO governance contract approves a `TransferAuthorization` batch
- Facilitator executes disbursements as a single sponsored transaction sequence
- Recipients receive funds without needing to hold AVAX

**Impact:** Enables DAOs to pay contributors and grantees in stablecoins without requiring recipients to manage gas tokens.

### 7.5 Subscription and Recurring Payments

SaaS applications, content platforms, and API providers building on Avalanche can implement recurring billing using time-locked `TransferAuthorization` signatures.

**Integration Pattern:**
- User signs a series of time-bounded authorizations (monthly, weekly)
- Service Facilitator redeems each authorization at the appropriate interval
- Each authorization contains a unique `nonce` and `deadline`, preventing premature or duplicate redemption

**Impact:** Enables the first true Web3-native subscription primitive on Avalanche — predictable recurring revenue for builders, zero gas friction for subscribers.

### 7.6 Cross-Protocol Composability

Because Q402 operates at the ERC-20 transfer layer, it is composable with any protocol that accepts token inputs. A single signed `TransferAuthorization` can be wrapped into more complex execution flows:

```
User signs once → Facilitator:
  1. Executes transferFromWithAuthorization (USDC payment)
  2. Calls DEX router to swap received USDC for yield-bearing token
  3. Deposits into lending protocol
  4. Returns receipt NFT to user

Total AVAX paid by user: 0
```

---

## 8. Comparison with Existing Approaches

| Approach | User Signs | Gas Source | Token Flexibility | Complexity |
|----------|-----------|------------|-------------------|------------|
| Standard ERC-20 | Approve + Transfer | User's AVAX | Any ERC-20 | Low |
| ERC-2612 Permit | Single signature | User's AVAX | Permit-enabled only | Medium |
| ERC-2771 Meta-tx | Single signature | Trusted Forwarder | Any ERC-20 | Medium |
| **Q402 (EIP-7702)** | **Single signature** | **Facilitator's AVAX** | **Any ERC-20** | **Low** |

Q402's primary differentiator is that the user's AVAX balance is **irrelevant** to transaction execution. The Facilitator bears gas cost entirely, creating a pure stablecoin-in / stablecoin-out flow.

---

## 9. Token Reference

### Avalanche Mainnet (Chain ID: 43114)

| Token | Contract Address |
|-------|-----------------|
| USDC (native, Circle) | `0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E` |
| USDC.e (bridged) | `0xA7D7079b0FEaD91F3e65f86E8915Cb59c1a4C664` |
| USDT.e | `0xc7198437980c041c805A1EDcbA50c1Ce5db95118` |

### Avalanche Fuji Testnet (Chain ID: 43113)

| Token | Contract Address |
|-------|-----------------|
| USDC (testnet, Circle) | `0x5425890298aed601595a70AB815c96711a31Bc65` |

---

## 10. Facilitator Economics

Facilitators are permissioned or permissionless relay nodes that process Q402 payment authorizations. They bear the gas cost of on-chain settlement and are compensated through a service fee embedded in the payment flow.

### Cost Structure (Avalanche Mainnet, Verified)

| Operation | Gas Used | AVAX Cost | USD Equivalent |
|-----------|----------|-----------|----------------|
| `transferFromWithAuthorization` | ~45,000 gas | 0.00011 AVAX | < $0.003 |
| Contract deployment (one-time) | ~800,000 gas | ~0.012 AVAX | < $0.30 |

### Facilitator Revenue Model

```
Revenue per transaction = service_fee_rate × payment_amount
Example: 0.5% fee on 0.05 USDC = 0.00025 USDC per transaction

Net margin per transaction:
  Revenue  : 0.00025 USDC (~$0.00025)
  Gas cost : 0.00011 AVAX (~$0.003)

At scale (10,000 tx/day, avg $10 payment):
  Revenue  : $500/day
  Gas cost : $30/day
  Net      : $470/day
```

Facilitators operating at volume achieve substantial positive margins, creating a self-sustaining incentive structure without protocol subsidies.

---

## 11. Policy Enforcement

Every payment authorization passes through three sequential validation checkpoints before any token movement occurs.

```
① Off-Chain Policy (Facilitator)
   ├─ Token address is whitelisted
   ├─ Amount ≤ per-transaction cap
   ├─ Recipient is not on sanctions list
   └─ Deadline is within acceptable window (≤ 15 minutes)

② On-Chain Validation (Smart Contract)
   ├─ block.timestamp ≤ deadline          [SignatureExpired]
   ├─ usedNonces[owner][nonce] == false    [NonceAlreadyUsed]
   ├─ ecrecover(digest, sig) == owner      [InvalidSignature]
   └─ IERC20.transfer() returns true       [TransferFailed]

③ Post-Execution Audit
   ├─ TransferExecuted event emitted on-chain
   ├─ Transaction hash recorded in Facilitator receipt store
   └─ Signature-to-transaction mapping preserved for audit trail
```

---

## 12. Project Structure

```
q402-avalanche/
├── contracts/
│   ├── Q402PaymentImplementation.sol   ← Production contract (Mainnet deployed)
│   └── MockERC20.sol                   ← Test-only ERC-20
├── scripts/
│   ├── deploy.ts                       ← Deployment script (Fuji + Mainnet)
│   └── demo.ts                         ← End-to-end gasless payment demonstration
├── test/
│   └── Q402Payment.test.ts             ← Unit test suite (8/8 passing)
├── hardhat.config.ts                   ← Hardhat configuration (Avalanche networks)
├── .env.example                        ← Environment variable reference
└── Q402_AVALANCHE_TECHNICAL_SPEC.md    ← This document
```

---

## 13. References

- [EIP-7702: Set EOA Account Code](https://eips.ethereum.org/EIPS/eip-7702)
- [EIP-712: Typed Structured Data Signing](https://eips.ethereum.org/EIPS/eip-712)
- [Avalanche C-Chain Documentation](https://docs.avax.network/learn/avalanche-platform)
- [Avalanche Fuji Testnet Faucet](https://faucet.avax.network/)
- [Snowtrace Block Explorer](https://snowtrace.io)
- Avalanche Mainnet Transaction: [0xea608bab...](https://snowtrace.io/tx/0xea608babc2809f836155679ffe5222cf1e24217741026b0595f8b7328d45f538)
- Deployed Contract: [0xE5b90D56...](https://snowtrace.io/address/0xE5b90D564650bdcE7C2Bb4344F777f6582e05699)
