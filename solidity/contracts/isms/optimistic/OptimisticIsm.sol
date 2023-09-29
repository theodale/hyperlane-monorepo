// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";
import {StaticMOfNAddressSetFactory} from "../../libs/StaticMOfNAddressSetFactory.sol";
import {StaticMessageIdMultisigIsm} from "./../multisig/StaticMultisigIsm.sol";
import {Message} from "../../libs/Message.sol";

/// @notice An optimistic ISM that allows watchers to flag messages and submodules as fraudulent.
/// @dev I have omitted event emission to reduce dev time.
/// Flow involves:
/// - Pre-verification via an external ISM via a preVerify() call
/// - Waiting for fraud window to pass => during this time m-of-n watchers can remove a message
/// - Confirming verification via a final verify() call
contract OptimisticIsm is IInterchainSecurityModule, Ownable {
    /// *** LIBRARIES ***

    using Message for bytes;

    /// *** STRUCTS ***

    // Holds pre-verified message state
    struct PreVerifiedMessage {
        // When the message's fraud window ends
        uint64 fraudWindowEnd;
        // The submodule used to pre-verify the message
        address usedSubmodule;
    }

    /// *** STATE VARIABLES ***

    /// @notice The length of the fraud window in seconds.
    uint64 public fraudWindow;

    /// @notice The number of watchers required to flag a submodule or message as fraudulent.
    uint256 public immutable watcherThreshold;

    /// @notice The address of the submodule currently being used to verify messages.
    address public submodule;

    /// @notice The multisig ISM used to determine watcher agreement.
    StaticMessageIdMultisigIsm public immutable watcherMultisigIsm;

    /// @notice Maps address => whether they are a watcher.
    mapping(address => bool) public isWatcher;

    /// @notice Maps message ID => a PreVerifiedMessage struct containing message state.
    mapping(bytes32 => PreVerifiedMessage) public preVerifiedMessages;

    /// @notice Maps submodule address to how many watchers have flagged it as fraudulent.
    mapping(address => uint256) public flags;

    /// @notice Maps watcher => submodule => whether they have flagged that submodule as fraudulent.
    mapping(address => mapping(address => bool)) hasFlagged;

    /// *** CONSTRUCTOR ***

    /// @notice Constructs the OptimisticIsm contract.
    /// @param _fraudWindow The length of the fraud window in seconds.
    /// @param _submodule The address of the submodule for  pre-verifying messages.
    /// @param _owner The owner of the contract.
    /// @param _watchers The addresses of the watchers.
    /// @param _threshold The number of watchers required to flag a submodule or message as fraudulent.
    /// @param _factory The address of a StaticMOfNAddressSetFactory that can deploy a watcher multisig.
    constructor(
        uint64 _fraudWindow,
        address _submodule,
        address _owner,
        address[] memory _watchers,
        uint8 _threshold,
        address _factory
    ) {
        // Set state variables
        fraudWindow = _fraudWindow;
        submodule = _submodule;
        watcherThreshold = _threshold;

        // Set owner
        _transferOwnership(_owner);

        // Deploy ERC-3448 MultiSig proxy with _watchers and _threshold metadata
        watcherMultisigIsm = StaticMessageIdMultisigIsm(
            StaticMOfNAddressSetFactory(_factory).deploy(_watchers, _threshold)
        );

        // Indicate watchers
        for (uint256 i; i < _watchers.length; ) {
            isWatcher[_watchers[i]] = true;
            unchecked {
                ++i;
            }
        }
    }

    /// *** VIEW METHODS ***

    /// @notice State ISM module type.
    /// @return The module type as an Types enum.
    function moduleType() external pure returns (uint8) {
        return uint8(IInterchainSecurityModule.Types.OPTIMISTIC);
    }

    // *** VERIFICATION METHODS ***

    /// @notice Provides final verification of a message.
    /// @param _metadata Metadata for the message.
    /// @param _message Formatted Hyperlane message.
    /// @return True if the message was verified.
    function preVerify(bytes calldata _metadata, bytes calldata _message)
        external
        returns (bool)
    {
        // Cache from storage
        address submodule_ = submodule;

        // Verify message using submodule
        require(
            IInterchainSecurityModule(submodule_).verify(_metadata, _message),
            "Message verification failed"
        );

        // Store message state under its ID
        // Save submodule pre-verified the message => could change & need to track number of flags
        preVerifiedMessages[_message.id()] = PreVerifiedMessage({
            fraudWindowEnd: uint64(block.timestamp) + fraudWindow,
            usedSubmodule: submodule_
        });

        return true;
    }

    /// @notice Pre-verfies a message via the current submodule and initiates the fraud window.
    /// @dev Assumes message replay is prevented via logic in calling contract.
    /// @param _metadata Metadata for the message.
    /// @param _message Formatted Hyperlane message.
    /// @return True if the message is verified
    function verify(bytes calldata _metadata, bytes calldata _message)
        external
        view
        returns (bool)
    {
        PreVerifiedMessage storage message = preVerifiedMessages[_message.id()];

        // Cache fraud window end
        uint64 end = message.fraudWindowEnd;

        // Check fraud window has passed
        require(end < block.timestamp, "Fraud window still ongoing");

        // Non-zero fraud window end indicates pre-verification of message
        // This also prevents arbitrary and deleted messages from being verified
        require(end != 0, "Message not pre-verified");

        // Check submodule has not been flagged as fraudulent
        require(
            flags[message.usedSubmodule] < watcherThreshold,
            "Submodule flagged as fraudulent"
        );

        return true;
    }

    // *** WATCHER METHODS ***

    /// @notice Removes a fraudulent message designated fraudulent by watchers.
    /// @dev Uses watcher multisig to verify that the message is fraudulent.
    /// This asssumes that the submodule used in pre-verify does not use the same m-of-n watcher signature quorum.
    /// Otherwise, pre-verification signatures could be used to remove the same messsage.
    /// @param _metadata Metadata for the message.
    /// @param _message Formatted Hyperlane message.
    function removeMessage(bytes calldata _metadata, bytes calldata _message)
        external
    {
        // This will revert if the message is not verified
        watcherMultisigIsm.verify(_metadata, _message);

        // Delete message
        delete preVerifiedMessages[_message.id()];
    }

    /// @notice Used by watchers to flag a submodule as fraudulent.
    /// @dev This is a one way operation.
    /// @param _submodule The submodule to flag as fraudulent.
    function markFraudulent(address _submodule) external {
        require(isWatcher[msg.sender], "Not a watcher");

        require(
            !hasFlagged[msg.sender][_submodule],
            "Already flagged submodule"
        );

        // Increment fraudulent submodule flags
        ++flags[_submodule];

        // Register that this watcher has flagged this submodule
        hasFlagged[msg.sender][_submodule] = true;
    }

    /// *** ADMIN METHODS ***

    /// @notice Updates fraud window to new value.
    /// @param _fraudWindow The new fraud window in seconds.
    function setFraudWindow(uint64 _fraudWindow) external onlyOwner {
        fraudWindow = _fraudWindow;
    }

    /// @notice Updates pre-verification ISM submodule to a new address.
    /// @param _submodule Adress of the new pre-verification ISM.
    function setSubmodule(address _submodule) external onlyOwner {
        submodule = _submodule;
    }
}
