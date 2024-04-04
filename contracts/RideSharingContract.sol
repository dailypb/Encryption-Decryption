// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ZkSnarkLibrary {
    enum RideStatus { Requested, Matched, Completed }

    struct Ride {
        address rider;
        uint256 pickupLocation;
        uint256 dropOffLocation;
        uint256 fare;
        RideStatus status;
        address driver;
        uint256[2] proof; // zk-SNARK proof
    }

    Ride[] public rides;
    mapping(address => uint256[]) public riderRides;
    mapping(address => uint256[]) public driverRides;

    event RideRequested(uint256 rideId, address rider);
    event RideMatched(uint256 rideId, address rider, address driver);
    event RideCompleted(uint256 rideId, address rider, address driver);

    function requestRide(uint256 _pickupLocation, uint256 _dropOffLocation, uint256 _fare, uint256[2] memory zkProof) external payable {
        require(msg.value >= _fare, "Insufficient payment");

        Ride memory newRide = Ride({
            rider: msg.sender,
            pickupLocation: _pickupLocation,
            dropOffLocation: _dropOffLocation,
            fare: _fare,
            status: RideStatus.Requested,
            driver: address(0),
            proof: zkProof
        });

        uint256 rideId = rides.length;
        rides.push(newRide);
        riderRides[msg.sender].push(rideId);

        emit RideRequested(rideId, msg.sender);
    }

    function matchRide(uint256 _rideId) external {
        require(_rideId < rides.length, "Invalid ride ID");
        Ride storage ride = rides[_rideId];
        require(ride.status == RideStatus.Requested, "Ride is not available");

        ride.status = RideStatus.Matched;
        ride.driver = msg.sender;
        driverRides[msg.sender].push(_rideId);

        emit RideMatched(_rideId, ride.rider, msg.sender);
    }

    function completeRide(uint256 _rideId) external {
        require(_rideId < rides.length, "Invalid ride ID");
        Ride storage ride = rides[_rideId];
        require(ride.status == RideStatus.Matched, "Ride is not matched");
        require(ride.driver == msg.sender, "You are not the driver of this ride");

        ride.status = RideStatus.Completed;

        // Transfer fare to the driver
        payable(ride.driver).transfer(ride.fare);

        emit RideCompleted(_rideId, ride.rider, ride.driver);
    }

    function getRidesForRider(address _rider) external view returns (Ride[] memory) {
        uint256[] memory rideIds = riderRides[_rider];
        Ride[] memory riderRidesArray = new Ride[](rideIds.length);
        for (uint256 i = 0; i < rideIds.length; i++) {
            riderRidesArray[i] = rides[rideIds[i]];
        }
        return riderRidesArray;
    }

    function getRidesForDriver(address _driver) external view returns (Ride[] memory) {
        uint256[] memory rideIds = driverRides[_driver];
        Ride[] memory driverRidesArray = new Ride[](rideIds.length);
        for (uint256 i = 0; i < rideIds.length; i++) {
            driverRidesArray[i] = rides[rideIds[i]];
        }
        return driverRidesArray;
    }
}
