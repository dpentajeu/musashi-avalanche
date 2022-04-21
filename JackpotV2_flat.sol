
// File: musashi-avax/contracts/Jackpot/interfaces/IMasterChief.sol

pragma solidity >=0.6.12;

interface IMasterChief {
    // function enterStaking(uint256 _amount) external;
    // function leaveStaking(uint256 _amount) external;
    // function userInfo(uint256 _amount, address _address) external view returns (uint, uint);
    // function pendingCake(uint256 _pid, address _user) external view returns (uint256);

    function stake(uint256 _amount, address recipient) external;
    function unstake(uint256 _amount, bool _trigger) external;
}

// File: musashi-avax/contracts/Jackpot/interfaces/ITicket.sol

pragma solidity >=0.6.12;

interface ITicket {
    function mintTo(address to, uint amount) external;
    function burnFrom(address from, uint amount) external;
}

// File: musashi-avax/contracts/Jackpot/interfaces/IERC20.sol

pragma solidity >=0.6.12;

interface IERC20 {
    function totalSupply() external virtual view returns (uint);
    function balanceOf(address tokenOwner) external virtual view returns (uint balance);
    function allowance(address tokenOwner, address spender) external virtual view returns (uint remaining);
    function transfer(address to, uint tokens) external virtual returns (bool success);
    function approve(address spender, uint tokens) external virtual returns (bool success);
    function transferFrom(address from, address to, uint tokens) external virtual returns (bool success);
    function mint(address _address, uint amount) external;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

// File: musashi-avax/contracts/Jackpot/libraries/TransferHelper.sol



pragma solidity >=0.6.0;

// helper methods for interacting with ERC20 tokens and sending ETH that do not consistently return true/false
library TransferHelper {
    function safeApprove(
        address token,
        address to,
        uint256 value
    ) internal {
        // bytes4(keccak256(bytes('approve(address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x095ea7b3, to, value));
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            'TransferHelper::safeApprove: approve failed'
        );
    }

    function safeTransfer(
        address token,
        address to,
        uint256 value
    ) internal {
        // bytes4(keccak256(bytes('transfer(address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0xa9059cbb, to, value));
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            'TransferHelper::safeTransfer: transfer failed'
        );
    }

    function safeTransferFrom(
        address token,
        address from,
        address to,
        uint256 value
    ) internal {
        // bytes4(keccak256(bytes('transferFrom(address,address,uint256)')));
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(0x23b872dd, from, to, value));
        require(
            success && (data.length == 0 || abi.decode(data, (bool))),
            'TransferHelper::transferFrom: transferFrom failed'
        );
    }

    function safeTransferETH(address to, uint256 value) internal {
        (bool success, ) = to.call{value: value}(new bytes(0));
        require(success, 'TransferHelper::safeTransferETH: ETH transfer failed');
    }
}

// File: musashi-avax/contracts/Jackpot/libraries/UniformRandomNumber.sol

/**
Copyright 2019 PoolTogether LLC

This file is part of PoolTogether.

PoolTogether is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation under version 3 of the License.

PoolTogether is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with PoolTogether.  If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity 0.6.12;

/**
 * @author Brendan Asselstine
 * @notice A library that uses entropy to select a random number within a bound.  Compensates for modulo bias.
 * @dev Thanks to https://medium.com/hownetworks/dont-waste-cycles-with-modulo-bias-35b6fdafcf94
 */
library UniformRandomNumber {
  /// @notice Select a random number without modulo bias using a random seed and upper bound
  /// @param _entropy The seed for randomness
  /// @param _upperBound The upper bound of the desired number
  /// @return A random number less than the _upperBound
  function uniform(uint256 _entropy, uint256 _upperBound) internal pure returns (uint256) {
    require(_upperBound > 0, "UniformRand/min-bound");
    uint256 min = -_upperBound % _upperBound;
    uint256 random = _entropy;
    while (true) {
      if (random >= min) {
        break;
      }
      random = uint256(keccak256(abi.encodePacked(random)));
    }
    return random % _upperBound;
  }
}


// File: musashi-avax/contracts/Jackpot/libraries/SortitionSumTreeFactory.sol

pragma solidity ^0.6.12;

/**
 *  @reviewers: [@clesaege, @unknownunknown1, @ferittuncer]
 *  @auditors: []
 *  @bounties: [<14 days 10 ETH max payout>]
 *  @deployments: []
 */

/**
 *  @title SortitionSumTreeFactory
 *  @author Enrique Piqueras - <epiquerass@gmail.com>
 *  @dev A factory of trees that keep track of staked values for sortition.
 */
library SortitionSumTreeFactory {
    /* Structs */

    struct SortitionSumTree {
        uint K; // The maximum number of childs per node.
        // We use this to keep track of vacant positions in the tree after removing a leaf. This is for keeping the tree as balanced as possible without spending gas on moving nodes around.
        uint[] stack;
        uint[] nodes;
        // Two-way mapping of IDs to node indexes. Note that node index 0 is reserved for the root node, and means the ID does not have a node.
        mapping(bytes32 => uint) IDsToNodeIndexes;
        mapping(uint => bytes32) nodeIndexesToIDs;
    }

    /* Storage */

    struct SortitionSumTrees {
        mapping(bytes32 => SortitionSumTree) sortitionSumTrees;
    }

    /* internal */

    /**
     *  @dev Create a sortition sum tree at the specified key.
     *  @param _key The key of the new tree.
     *  @param _K The number of children each node in the tree should have.
     */
    function createTree(SortitionSumTrees storage self, bytes32 _key, uint _K) internal {
        SortitionSumTree storage tree = self.sortitionSumTrees[_key];
        require(tree.K == 0, "Tree already exists.");
        require(_K > 1, "K must be greater than one.");
        tree.K = _K;
        tree.stack = new uint[](0);
        tree.nodes = new uint[](0);
        tree.nodes.push(0);
    }

    /**
     *  @dev Set a value of a tree.
     *  @param _key The key of the tree.
     *  @param _value The new value.
     *  @param _ID The ID of the value.
     *  `O(log_k(n))` where
     *  `k` is the maximum number of childs per node in the tree,
     *   and `n` is the maximum number of nodes ever appended.
     */
    function set(SortitionSumTrees storage self, bytes32 _key, uint _value, bytes32 _ID) internal {
        SortitionSumTree storage tree = self.sortitionSumTrees[_key];
        uint treeIndex = tree.IDsToNodeIndexes[_ID];

        if (treeIndex == 0) { // No existing node.
            if (_value != 0) { // Non zero value.
                // Append.
                // Add node.
                if (tree.stack.length == 0) { // No vacant spots.
                    // Get the index and append the value.
                    treeIndex = tree.nodes.length;
                    tree.nodes.push(_value);

                    // Potentially append a new node and make the parent a sum node.
                    if (treeIndex != 1 && (treeIndex - 1) % tree.K == 0) { // Is first child.
                        uint parentIndex = treeIndex / tree.K;
                        bytes32 parentID = tree.nodeIndexesToIDs[parentIndex];
                        uint newIndex = treeIndex + 1;
                        tree.nodes.push(tree.nodes[parentIndex]);
                        delete tree.nodeIndexesToIDs[parentIndex];
                        tree.IDsToNodeIndexes[parentID] = newIndex;
                        tree.nodeIndexesToIDs[newIndex] = parentID;
                    }
                } else { // Some vacant spot.
                    // Pop the stack and append the value.
                    treeIndex = tree.stack[tree.stack.length - 1];
                    tree.stack.pop();
                    tree.nodes[treeIndex] = _value;
                }

                // Add label.
                tree.IDsToNodeIndexes[_ID] = treeIndex;
                tree.nodeIndexesToIDs[treeIndex] = _ID;

                updateParents(self, _key, treeIndex, true, _value);
            }
        } else { // Existing node.
            if (_value == 0) { // Zero value.
                // Remove.
                // Remember value and set to 0.
                uint value = tree.nodes[treeIndex];
                tree.nodes[treeIndex] = 0;

                // Push to stack.
                tree.stack.push(treeIndex);

                // Clear label.
                delete tree.IDsToNodeIndexes[_ID];
                delete tree.nodeIndexesToIDs[treeIndex];

                updateParents(self, _key, treeIndex, false, value);
            } else if (_value != tree.nodes[treeIndex]) { // New, non zero value.
                // Set.
                bool plusOrMinus = tree.nodes[treeIndex] <= _value;
                uint plusOrMinusValue = plusOrMinus ? _value - tree.nodes[treeIndex] : tree.nodes[treeIndex] - _value;
                tree.nodes[treeIndex] = _value;

                updateParents(self, _key, treeIndex, plusOrMinus, plusOrMinusValue);
            }
        }
    }

    /* internal Views */

    /**
     *  @dev Query the leaves of a tree. Note that if `startIndex == 0`, the tree is empty and the root node will be returned.
     *  @param _key The key of the tree to get the leaves from.
     *  @param _cursor The pagination cursor.
     *  @param _count The number of items to return.
     *  @return startIndex The index at which leaves start
     *  @return values The values of the returned leaves
     *  @return hasMore Whether there are more for pagination.
     *  `O(n)` where
     *  `n` is the maximum number of nodes ever appended.
     */
    function queryLeafs(
        SortitionSumTrees storage self,
        bytes32 _key,
        uint _cursor,
        uint _count
    ) internal view returns(uint startIndex, uint[] memory values, bool hasMore) {
        SortitionSumTree storage tree = self.sortitionSumTrees[_key];

        // Find the start index.
        for (uint i = 0; i < tree.nodes.length; i++) {
            if ((tree.K * i) + 1 >= tree.nodes.length) {
                startIndex = i;
                break;
            }
        }

        // Get the values.
        uint loopStartIndex = startIndex + _cursor;
        values = new uint[](loopStartIndex + _count > tree.nodes.length ? tree.nodes.length - loopStartIndex : _count);
        uint valuesIndex = 0;
        for (uint j = loopStartIndex; j < tree.nodes.length; j++) {
            if (valuesIndex < _count) {
                values[valuesIndex] = tree.nodes[j];
                valuesIndex++;
            } else {
                hasMore = true;
                break;
            }
        }
    }

    /**
     *  @dev Draw an ID from a tree using a number. Note that this function reverts if the sum of all values in the tree is 0.
     *  @param _key The key of the tree.
     *  @param _drawnNumber The drawn number.
     *  @return ID The drawn ID.
     *  `O(k * log_k(n))` where
     *  `k` is the maximum number of childs per node in the tree,
     *   and `n` is the maximum number of nodes ever appended.
     */
    function draw(SortitionSumTrees storage self, bytes32 _key, uint _drawnNumber) internal view returns(bytes32 ID) {
        SortitionSumTree storage tree = self.sortitionSumTrees[_key];
        uint treeIndex = 0;
        uint currentDrawnNumber = _drawnNumber % tree.nodes[0];

        while ((tree.K * treeIndex) + 1 < tree.nodes.length)  // While it still has children.
            for (uint i = 1; i <= tree.K; i++) { // Loop over children.
                uint nodeIndex = (tree.K * treeIndex) + i;
                uint nodeValue = tree.nodes[nodeIndex];

                if (currentDrawnNumber >= nodeValue) currentDrawnNumber -= nodeValue; // Go to the next child.
                else { // Pick this child.
                    treeIndex = nodeIndex;
                    break;
                }
            }
        
        ID = tree.nodeIndexesToIDs[treeIndex];
    }

    /** @dev Gets a specified ID's associated value.
     *  @param _key The key of the tree.
     *  @param _ID The ID of the value.
     *  @return value The associated value.
     */
    function stakeOf(SortitionSumTrees storage self, bytes32 _key, bytes32 _ID) internal view returns(uint value) {
        SortitionSumTree storage tree = self.sortitionSumTrees[_key];
        uint treeIndex = tree.IDsToNodeIndexes[_ID];

        if (treeIndex == 0) value = 0;
        else value = tree.nodes[treeIndex];
    }

    function total(SortitionSumTrees storage self, bytes32 _key) internal view returns (uint) {
        SortitionSumTree storage tree = self.sortitionSumTrees[_key];
        if (tree.nodes.length == 0) {
            return 0;
        } else {
            return tree.nodes[0];
        }
    }

    /* Private */

    /**
     *  @dev Update all the parents of a node.
     *  @param _key The key of the tree to update.
     *  @param _treeIndex The index of the node to start from.
     *  @param _plusOrMinus Wether to add (true) or substract (false).
     *  @param _value The value to add or substract.
     *  `O(log_k(n))` where
     *  `k` is the maximum number of childs per node in the tree,
     *   and `n` is the maximum number of nodes ever appended.
     */
    function updateParents(SortitionSumTrees storage self, bytes32 _key, uint _treeIndex, bool _plusOrMinus, uint _value) private {
        SortitionSumTree storage tree = self.sortitionSumTrees[_key];

        uint parentIndex = _treeIndex;
        while (parentIndex != 0) {
            parentIndex = (parentIndex - 1) / tree.K;
            tree.nodes[parentIndex] = _plusOrMinus ? tree.nodes[parentIndex] + _value : tree.nodes[parentIndex] - _value;
        }
    }
}
// File: musashi-avax/contracts/Jackpot/libraries/SafeMath.sol

pragma solidity ^0.6.12;

// ----------------------------------------------------------------------------
// Safe maths
// ----------------------------------------------------------------------------
library SafeMath {
    function add(uint a, uint b) internal pure returns (uint c) {
        c = a + b;
        require(c >= a, 'SafeMath:INVALID_ADD');
    }

    function sub(uint a, uint b) internal pure returns (uint c) {
        require(b <= a, 'SafeMath:OVERFLOW_SUB');
        c = a - b;
    }

    function mul(uint a, uint b, uint decimal) internal pure returns (uint) {
        uint dc = 10**decimal;
        uint c0 = a * b;
        require(a == 0 || c0 / a == b, "SafeMath: multiple overflow");
        uint c1 = c0 + (dc / 2);
        require(c1 >= c0, "SafeMath: multiple overflow");
        uint c2 = c1 / dc;
        return c2;
    }

    function div(uint256 a, uint256 b, uint decimal) internal pure returns (uint256) {
        require(b != 0, "SafeMath: division by zero");
        uint dc = 10**decimal;
        uint c0 = a * dc;
        require(a == 0 || c0 / a == dc, "SafeMath: division internal");
        uint c1 = c0 + (b / 2);
        require(c1 >= c0, "SafeMath: division internal");
        uint c2 = c1 / b;
        return c2;
    }
}

// File: musashi-avax/contracts/Jackpot/JackpotV2.sol

pragma solidity ^0.6.12;








contract JackpotV2 {
    using SortitionSumTreeFactory for SortitionSumTreeFactory.SortitionSumTrees;
    using SafeMath for uint;

    struct Player {
        uint deposit;
        uint weightage;
        uint deposit_timestamp;
        uint last_claim_block;
        uint reward_debt;
    }

    struct DepositLog {
        address account;
        uint session_id;
        uint amount;
        uint timestamp;
        uint block_no;
    }

    struct CompleteInfo {
        uint      timestamp;
        uint      number_of_winner;
        uint      randomness;
        address[] winners;
        uint[]    amounts;
    }

    bytes32 constant private TREE_KEY        = keccak256("JACKPOT");
    uint256 constant private MAX_TREE_LEAVES = 5;
    uint256 constant private MAX_INT         = uint256(-1);
    uint    constant private DECIMAL         = 9;
    uint    constant private PER_UNIT        = 1000000000;
    uint    constant private HUNDRED_UNIT    = 100000000000;

    /*
    * reward distribution
    */
    uint   public rate_platform;
    uint[] public winner_rates;

    /*
    * claim platform token
    */
    uint public acc_token_per_share;
    
    /*
    * withdraw penatly
    */
    uint public withdraw_penalty_minute = 4320; // initial lock 72 hour
    uint public penalty_rate = 25000000;        // initial 2.5% 

    /*
    * jackpot session configuration
    */
    uint public session_minute;         // session duration in minute (unit is Ether)
    uint public session_startTimestamp; // session start time
    uint public session_endTimestamp;   // session end time
    uint public number_of_winner;       // total count of winner (unit is Ether)
    uint public block_per_session;      // block per session (9 Decimal) (based on session_minute)

    /*
    * jackpot profile
    */
    uint      public session_id;
    uint      public total_deposit;
    uint      public total_weightage;
    uint      public session_init_block;
    uint      public rng_seed;
    uint      public deposit_id;
    uint      public claimable_reserve;
    address[] public coowner_list;

    /*
    * wonderland
    */
    address public stake_pool;
    address public stake_helper;

    /*
    * jackpot setting
    */
    address public pot_owner;      // jackpot owner (multi-owner)
    address public company;        // company fund receiving
    address public memo;           // Memo(ries) token
    address public deposit_token;  // deposit token to play
    address public ticket;         // ticket proven user joined pool
    
    /*
    * jackpot control
    */
    bool public deposit_paused;
    bool public withdraw_paused;
    bool public claim_stopped;

    SortitionSumTreeFactory.SortitionSumTrees private sortitionSumTrees;

    mapping (address => Player)       public  player;
    mapping (address => bool)         public  access_permission;
    mapping (uint    => CompleteInfo) private complete_history;
    mapping (uint    => DepositLog)   public  deposit_log;

    event Deposit(address player, uint amount);
    event Withdraw(address player, uint amount);
    event CompletePot(address[] winners, uint randomness, uint timestamp);
    event UpdatePotSetting(uint no_of_winner, uint day, uint block_per_session);
    event UpdateControl(bool deposit_paused, bool withdraw_paused, bool claim_stopped);
    event UpdateAccessPermission(address _address, bool status);
    event UpdateRewardRates(uint rate_platform, uint[] win_rates);
    event TransferPotOwner(address new_owner);

    modifier isPotEnd() {
        require(session_endTimestamp != 0, "pot end not initialize");
        require(getPotEnd() == true, "pot not end");
        _;
    }

    modifier onlyPotOwner() {
        require(msg.sender == pot_owner, "not pot owner");
        _;
    }

    modifier hasAccessPermission() {
        require(access_permission[msg.sender], "no access permission");
        _;
    }

    constructor(address _ticket) public {
        pot_owner         = msg.sender;
        company           = msg.sender;
        number_of_winner  = 3;
        session_minute    = 10080; // 7 days
        block_per_session = 201600000000000; // 7 days (9 decimal)
        deposit_token     = 0xb54f16fB19478766A268F172C9480f8da1a7c9C3; // TIME
        ticket            = _ticket;

        // wonderland staking pool (mainnet)
        stake_helper = 0x096BBfB78311227b805c968b070a81D358c13379;
        stake_pool   = 0x4456B87Af11e87E329AB7d7C7A246ed1aC2168B9;
        memo         = 0x136Acd46C134E8269052c62A67042D6bDeDde3C9;

        // reward distribution (remaining will distribute to all staker)
        rate_platform = 50000000;
        winner_rates.push(400000000); // first place
        winner_rates.push(200000000); // second place
        winner_rates.push(150000000); // third place

        // initialize sortition tree
        sortitionSumTrees.createTree(TREE_KEY, MAX_TREE_LEAVES);

        access_permission[msg.sender] = true;
    }

    /*
    * player deposit
    */
    function deposit(uint amount) external {
        require(!deposit_paused, "deposit paused");
        require(amount > 0, "invalid deposit amount");
        require(
            (block_per_session > 0) && (session_init_block > 0),
            "invalid block configure"
        );

        // claim reward token
        claim();

        // join jackpot
        TransferHelper.safeTransferFrom(deposit_token, msg.sender, address(this), amount);
        _playerEntry(msg.sender, amount);

        // stake into staking pool
        _enterStake(IERC20(deposit_token).balanceOf(address(this)));

        player[msg.sender].last_claim_block = block.number;
        player[msg.sender].reward_debt      = acc_token_per_share.mul(player[msg.sender].weightage, DECIMAL);

        emit Deposit(msg.sender, amount);

        deposit_log[deposit_id].account    = msg.sender;
        deposit_log[deposit_id].session_id = session_id;
        deposit_log[deposit_id].amount     = amount;
        deposit_log[deposit_id].timestamp  = block.timestamp;
        deposit_log[deposit_id].block_no   = block.number;

        deposit_id = deposit_id.add(1);
    }

    /*
    * player withdrawal staked token
    */
    function withdraw(uint amount) external {
        require(!withdraw_paused, "withdraw paused");
        require(amount > 0, "invalid withdraw amount");
        require(player[msg.sender].deposit >= amount, "insufficient withdraw balance");
        require(IERC20(ticket).balanceOf(msg.sender) >= amount, "insufficient ticket balance");

        // claim reward token
        claim();

        // withdraw from staking pool
        if (IERC20(memo).allowance(address(this), stake_pool) <= amount) {
            TransferHelper.safeApprove(memo, stake_pool, MAX_INT);
        }
        IMasterChief(stake_pool).unstake(amount, true);

        // deduct player entity from jackpot
        ITicket(ticket).burnFrom(msg.sender, amount);

        // recalculate user weightage based on cake allocation
        uint cake_remain        = player[msg.sender].deposit.sub(amount);
        uint allocate_rate      = cake_remain.div(player[msg.sender].deposit, DECIMAL);
        uint remain_weightage   = player[msg.sender].weightage.mul(allocate_rate, DECIMAL);
        uint deducted_weightage = player[msg.sender].weightage.sub(remain_weightage);
        
        total_weightage              = total_weightage.sub(deducted_weightage);
        player[msg.sender].weightage = remain_weightage;
        sortitionSumTrees.set(TREE_KEY, player[msg.sender].weightage, bytes32(uint256(msg.sender)));

        // player withdrawal
        total_deposit = total_deposit.sub(amount);
        player[msg.sender].deposit = player[msg.sender].deposit.sub(amount);

        (uint withdrawable,,,) = getActualWithdrawable(msg.sender, amount);
        TransferHelper.safeTransfer(deposit_token, msg.sender, withdrawable);

        // update reward token claim info
        player[msg.sender].reward_debt = acc_token_per_share.mul(player[msg.sender].weightage, DECIMAL);

        // stake into staking pool
        _enterStake(IERC20(deposit_token).balanceOf(address(this)));

        emit Withdraw(msg.sender, withdrawable);
    }

    /*
    * retrieve player withdrawable amount after penalty rules
    */
    function getActualWithdrawable(address _address, uint amount) public view returns (uint, bool, uint, uint) {
        uint last_deposit  = player[_address].deposit_timestamp;
        uint penalty_until = last_deposit.add(withdraw_penalty_minute * 60);
        bool has_penalty   = (block.timestamp <= penalty_until);
        
        if (has_penalty) {
            amount = amount.sub(amount.mul(penalty_rate, DECIMAL));
        }

        return (amount, has_penalty, penalty_until, penalty_rate);
    }
    
    /*
    * retrieve player is under withdrawal penalty info
    */
    function getPlayerWithdrawPenalty(address _address) external view returns (bool, uint, uint) {
        (, bool has_penalty, uint penalty_until, uint _penalty_rate) = getActualWithdrawable(_address, 1 * 10**DECIMAL);
        return (has_penalty, penalty_until, _penalty_rate);
    }

    /*
    * retrieve jackpot is ended status
    */
    function getPotEnd() public view returns (bool) {
        return (session_endTimestamp < block.timestamp);
    }

    /*
    * complete the current jackpot session
    */
    function completePot() external isPotEnd {
        uint randomness     = _getRngSeed();
        uint sponsor_reward  = IERC20(deposit_token).balanceOf(address(this));
        
        (address[] memory winners, uint winners_length) = _pickWinners(randomness, total_weightage, number_of_winner);

        // harvest from staking pool
        uint staked = IERC20(memo).balanceOf(address(this));
        uint pool_reward = 0;

        if (staked >= total_deposit) {
            pool_reward = staked.sub(total_deposit);
        }

        if (IERC20(memo).allowance(address(this), stake_pool) <= pool_reward) {
            TransferHelper.safeApprove(memo, stake_pool, MAX_INT);
        }
        IMasterChief(stake_pool).unstake(pool_reward, true);

        // total jackpot reward of this session
        uint total_reward = sponsor_reward.add(pool_reward).sub(claimable_reserve);
        uint sum_winner   = 0;

        // allocation for winner reward
        for (uint i = 0; i < winners_length; i++) {
            _claim(winners[i]);
            uint _win = total_reward.mul(winner_rates[i], DECIMAL);
            _playerEntry(winners[i], _win);
            complete_history[session_id].winners.push(winners[i]);
            complete_history[session_id].amounts.push(_win);
            sum_winner = sum_winner.add(_win);
            player[winners[i]].reward_debt = acc_token_per_share.mul(player[winners[i]].weightage, DECIMAL);
        }

        // allocation for platform
        uint platform_reward = total_reward.mul(rate_platform, DECIMAL);
        if (platform_reward > 0) {
            TransferHelper.safeTransfer(deposit_token, company, platform_reward);
        }

        // remaining reward distribute to staker
        if (total_reward > sum_winner.add(platform_reward)) {
            _updateAccTokenPerShare(total_reward.sub(sum_winner.add(platform_reward)), total_weightage);
            claimable_reserve = claimable_reserve.add(total_reward.sub(sum_winner.add(platform_reward)));
        }

        // restake token to staking pool
        _enterStake(IERC20(deposit_token).balanceOf(address(this)));

        // start new session
        session_startTimestamp = session_endTimestamp;
        session_endTimestamp   = session_endTimestamp.add(session_minute * 60);
        
        // clear all coowner for this session
        delete coowner_list;

        complete_history[session_id].number_of_winner = winners_length;
        complete_history[session_id].randomness       = randomness;
        complete_history[session_id].timestamp        = block.timestamp;
        session_id = session_id.add(1);

        emit CompletePot(winners, randomness, block.timestamp);
    }

    /*
    * player claim platform token
    */
    function claim() public {
        _claim(msg.sender);
    }

    /*
    * retrieve player claimable reward token amount
    */
    function getClaimable() public view returns (uint) {
        return getRewardAmount(msg.sender);
    }

    /*
    * retrieve player wining rate
    */
    function winRate(address _player) external view returns (uint) {
        if (total_weightage <= 0) {
            return 0;
        }
        return player[_player].weightage.div(total_weightage, DECIMAL);
    }

    /*
    * retrieve complete pot info by session id
    */
    function getCompleteHistory(uint _session_id) external view returns (uint, uint, address[] memory, uint[] memory, uint) {
        address[] memory winners = complete_history[_session_id].winners;
        uint[]    memory amounts = complete_history[_session_id].amounts;
        uint randomness  = complete_history[_session_id].randomness;
        uint _num_winner = complete_history[_session_id].number_of_winner;
        uint timestamp   = complete_history[_session_id].timestamp;
        return (_num_winner, randomness, winners, amounts, timestamp);
    }
    
    /*
    * init the pot session of the first time
    * @param start : input 0 to follow current timestamp; input value to specific start time
    */
    function initPot(uint start) external hasAccessPermission {
        require(session_minute > 0, "session duration cannot be zero");

        if (start <= 0) {
            session_startTimestamp = block.timestamp;
        } else {
            session_startTimestamp = start;
        }
        
        session_endTimestamp   = session_startTimestamp.add(session_minute * 60);
        
        if (session_init_block <= 0) {
            session_init_block = block.number;
        }
    }
    
    /*
    * update withdraw penalty setting
    */
    function updateWithdrawPenalty(uint wminute, uint wrate) external hasAccessPermission {
        withdraw_penalty_minute = wminute;
        penalty_rate            = wrate;
    }

    /*
    * update pot setting
    */
    function updatePotSetting(uint no_of_winner, uint _session_minute, uint _block_per_session) external hasAccessPermission {
        number_of_winner  = no_of_winner;
        session_minute    = _session_minute;
        block_per_session = _block_per_session;
        emit UpdatePotSetting(number_of_winner, session_minute, block_per_session);
    }
    
    /*
    * update pot control
    */
    function updateControl(bool _dpaused, bool _wpaused, bool _cstopped) external hasAccessPermission {
        deposit_paused  = _dpaused;
        withdraw_paused = _wpaused;
        claim_stopped   = _cstopped;
        emit UpdateControl(_dpaused, _wpaused, _cstopped);
    }

    /*
    * update company receiving address
    */
    function updateCompany(address _address) external hasAccessPermission {
        company = _address;
    }

    /*
    * update deposit token
    */
    function updateDepositToken(address _address) external hasAccessPermission {
        deposit_token = _address;
    }

    /*
    * update memo token
    */
    function updateMemoToken(address _address) external hasAccessPermission {
        memo = _address;
    }
    
    /*
    * update session end timestamp
    */
    function updateSessionEndTimestamp(uint _end) external hasAccessPermission {
        session_endTimestamp = _end;
    }

    /*
    * update stakig pool setting related
    */
    function updateStakeSetting(address _stake_pool, address _stake_helper) external hasAccessPermission {
        stake_pool   = _stake_pool;
        stake_helper = _stake_helper;
    }

    /*
    * update reward distribution
    */
    function updateRewardRates(uint _rate_platform, uint[] memory _rates) external hasAccessPermission {
        // remove old
        while (true) {
            if (winner_rates.length > 0) {
                winner_rates.pop();
            } else {
                break;
            }
        }

        // insert new setting
        uint sum_rate;
        for (uint i = 0; i < _rates.length; i++) {
            winner_rates.push(_rates[i]);
            sum_rate = sum_rate.add(_rates[i]);
        }

        require(_rate_platform.add(sum_rate) <= PER_UNIT, "invalid rate value");

        rate_platform = _rate_platform;

        emit UpdateRewardRates(_rate_platform, _rates);
    }

    /*
    * add co-owner for current session
    */
    function addCoOwner(address _address) external hasAccessPermission {
        require(coowner_list.length < number_of_winner, "coowner list exceed number of winner");
        coowner_list.push(_address);
    }

    /*
    * remove co-owner for current session
    */
    function removeCoOwner(address _address) external hasAccessPermission {
        uint index = 0;
        for (uint i = 0; i < coowner_list.length; i++) {
            if (coowner_list[i] == _address) {
                index = i;
                break;
            }
        }

        if (index >= coowner_list.length) return;

        for (uint i = index; i < coowner_list.length - 1; i++){
            coowner_list[i] = coowner_list[i+1];
        }

        coowner_list.pop();
    }

    /*
    * update access permission
    */
    function updateAccessPermission(address _address, bool status) external onlyPotOwner {
        access_permission[_address] = status;
        emit UpdateAccessPermission(_address, status);
    }

    /*
    * transfer jackpot ownership (multi-owner)
    */
    function transferPotOwner(address new_owner) external onlyPotOwner {
        pot_owner = new_owner;
        emit TransferPotOwner(pot_owner);
    }

    /*
    * for emergency transfer ether back to owner
    */
    function emergencyTransferEther(uint amount) external onlyPotOwner {
        TransferHelper.safeTransferETH(pot_owner, amount);
    }

    /*
    * for emergency transfer any token back to owner
    */
    function emergencyTransferToken(address token, uint amount) external onlyPotOwner {
        TransferHelper.safeTransfer(token, pot_owner, amount);
    }

    /*
    * for emergency harvest from DEX and back to owner
    */
    function emergencyTransferDexAsset() external onlyPotOwner {
        uint staked = IERC20(memo).balanceOf(address(this));
        if (IERC20(memo).allowance(address(this), stake_pool) <= staked) {
            TransferHelper.safeApprove(memo, stake_pool, MAX_INT);
        }

        IMasterChief(stake_pool).unstake(staked, true);
        uint balance = IERC20(deposit_token).balanceOf(address(this));
        TransferHelper.safeTransfer(deposit_token, pot_owner, balance);
    }

    function _updateAccTokenPerShare(uint reward, uint _total_deposit) internal {
        uint result = 0;
        if (_total_deposit > 0) {
            result = reward.div(_total_deposit, DECIMAL);
        }
        acc_token_per_share = acc_token_per_share.add(result);
    }

    function _claim(address _address) internal {
        if (!claim_stopped && player[_address].last_claim_block < block.number) {
            uint claimable = getRewardAmount(_address);
            if (claimable > 0 && claimable_reserve >= claimable) {

                // if contract insufficient balance to transfer, unstake from staking pool
                // to cover the remaining balance
                uint pool_balance = IERC20(deposit_token).balanceOf(address(this));
                if (pool_balance < claimable) {
                    uint diff = claimable.sub(pool_balance);
                    if (IERC20(memo).allowance(address(this), stake_pool) <= diff) {
                        TransferHelper.safeApprove(memo, stake_pool, MAX_INT);
                    }
                    IMasterChief(stake_pool).unstake(diff, true);
                }

                TransferHelper.safeTransfer(deposit_token, _address, claimable);
                player[_address].last_claim_block = block.number;
                claimable_reserve = claimable_reserve.sub(claimable);
            }
            player[_address].reward_debt = acc_token_per_share.mul(player[_address].weightage, DECIMAL);
        }
    }

    function getRewardAmount(address _address) public view returns (uint) {
        if (total_weightage <= 0) {
            return (0);
        }

        uint user_staked = player[_address].weightage;
        uint user_debt   = player[_address].reward_debt;
        uint claimable   = acc_token_per_share.mul(user_staked, DECIMAL).sub(user_debt);

        return (claimable);
    }

    function _getRngSeed() internal returns(uint) {
        uint randomness = uint(keccak256(abi.encode(msg.sender, block.number, rng_seed)));
        rng_seed = randomness;
        return randomness;
    }

    function _enterStake(uint amount) internal {
        if (IERC20(deposit_token).allowance(address(this), stake_helper) <= amount) {
            TransferHelper.safeApprove(deposit_token, stake_helper, MAX_INT);
        }
        IMasterChief(stake_helper).stake(amount, address(this));
    }

    function _pickWinners(uint randomness, uint _total_weightage, uint number_winner) internal returns (address[] memory, uint) {
        address[] memory winners = new address[](number_winner);
        uint expanded_randomness = randomness;
        uint random_index        = 0;
        uint winner_index        = 0;
        uint temp_weightage      = _total_weightage;

        if (_total_weightage <= 0) {
            return (new address[](0), 0);
        }

        // non-repeat winner algorithm
        uint player_length = number_winner.sub(coowner_list.length);
        uint[] memory selected_weightage = new uint[](number_winner);
        
        for (uint i = 0; i < coowner_list.length; i++) {
            selected_weightage[winner_index] = player[coowner_list[i]].weightage;
            sortitionSumTrees.set(TREE_KEY, 0, bytes32(uint256(coowner_list[i])));

            winners[winner_index] = coowner_list[i];
            winner_index          = winner_index.add(1);
        }

        for (uint i = 0; i < player_length; i++) {
            random_index          = UniformRandomNumber.uniform(expanded_randomness, temp_weightage);
            winners[winner_index] = address(uint256(sortitionSumTrees.draw(TREE_KEY, random_index)));
            expanded_randomness   = uint256(keccak256(abi.encode(randomness, i)));

            temp_weightage = temp_weightage.sub(player[winners[winner_index]].weightage);
            selected_weightage[winner_index] = player[winners[winner_index]].weightage;
            sortitionSumTrees.set(TREE_KEY, 0, bytes32(uint256(winners[winner_index])));
            winner_index = winner_index.add(1);
            
            if (sortitionSumTrees.total(TREE_KEY) <= 0) {
                break;
            }
        }
        
        for (uint i = 0; i < winner_index; i++) {
            sortitionSumTrees.set(TREE_KEY, selected_weightage[i], bytes32(uint256(winners[i])));
        }

        return (winners, winner_index);
    }

    function _playerEntry(address _address, uint amount) internal {
        player[_address].deposit = player[_address].deposit.add(amount);
        total_deposit            = total_deposit.add(amount);

        // weightage = user_deposit * (1 - ((deposit_block - session init block)/block_per_session/100))
        uint block_diff  = block.number.sub(session_init_block);
        block_diff       = block_diff * 10**DECIMAL;
        uint weight_rate = block_diff.div(block_per_session, DECIMAL).div(HUNDRED_UNIT, DECIMAL);
        weight_rate      = PER_UNIT.sub(weight_rate);

        uint weightage = amount.mul(weight_rate, DECIMAL);

        total_weightage = total_weightage.add(weightage);
        player[_address].weightage = player[_address].weightage.add(weightage);
        player[_address].deposit_timestamp = block.timestamp;
        sortitionSumTrees.set(TREE_KEY, player[_address].weightage, bytes32(uint256(_address)));

        // Send ticket to user
        ITicket(ticket).mintTo(_address, amount);
    }
}
