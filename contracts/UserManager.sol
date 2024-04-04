// UserManager.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UserManager {
    struct User {
        string name;
        uint256 location;
        bool isDriver;
        bool isVerified;
        string verificationHash;
    }

    mapping(address => User) public users;

    event UserSignedUp(address userAddress, string name, uint256 location, bool isDriver);
    event UserVerified(address userAddress, string verificationHash);

    // Function to sign up a user (both riders and drivers)
    function signUp(string memory _name, uint256 _location, bool _isDriver) external {
        require(bytes(_name).length > 0, "Name is required");
        require(users[msg.sender].location == 0, "User already signed up");

        users[msg.sender] = User({
            name: _name,
            location: _location,
            isDriver: _isDriver,
            isVerified: false,
            verificationHash: ""
        });

        emit UserSignedUp(msg.sender, _name, _location, _isDriver);
    }

    // Function to verify a user or driver
    function verifyUser(address _userAddress, string memory _verificationHash) external {
        require(msg.sender == _userAddress || users[msg.sender].isDriver, "You are not authorized to verify users");
        require(bytes(users[_userAddress].verificationHash).length == 0, "User is already verified");

        users[_userAddress].verificationHash = _verificationHash;
        users[_userAddress].isVerified = true;

        emit UserVerified(_userAddress, _verificationHash);
    }
}
