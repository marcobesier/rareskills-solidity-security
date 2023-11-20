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
