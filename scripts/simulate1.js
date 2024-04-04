const Web3 = require('web3');
const web3 = new Web3('YOUR_ETHEREUM_NODE_URL'); // Replace with your Ethereum node URL
const userManagerABI = []; // ABI for UserManager contract
const rideManagerABI = []; // ABI for RideManager contract

const userManagerAddress = 'USER_MANAGER_CONTRACT_ADDRESS';
const rideManagerAddress = 'RIDE_MANAGER_CONTRACT_ADDRESS';

const userManager = new web3.eth.Contract(userManagerABI, userManagerAddress);
const rideManager = new web3.eth.Contract(rideManagerABI, rideManagerAddress);

const NUM_USERS = 5; // Specify the number of users to create
const NUM_DRIVERS = 3; // Specify the number of drivers to create

function generateRandomName() {
  const names = ['Alice', 'Bob', 'Charlie', 'David', 'Eve', 'Frank', 'Grace', 'Helen', 'Ivy', 'Jack'];
  const randomIndex = Math.floor(Math.random() * names.length);
  return names[randomIndex];
}

function generateRandomLocation() {
  return Math.floor(Math.random() * 10) + 1; // Generate a random location between 1 and 10
}

async function createUsersAndDrivers() {
  const users = [];
  const drivers = [];

  for (let i = 0; i < NUM_USERS; i++) {
    const name = generateRandomName();
    const location = generateRandomLocation();
    const userAddress = `USER_ADDRESS_${i}`;
    users.push({ name, location, isDriver: false, address: userAddress });
  }

  for (let i = 0; i < NUM_DRIVERS; i++) {
    const name = generateRandomName();
    const location = generateRandomLocation();
    const driverAddress = `DRIVER_ADDRESS_${i}`;
    drivers.push({ name, location, isDriver: true, address: driverAddress });
  }

  console.log(`Generated ${NUM_USERS} users and ${NUM_DRIVERS} drivers`);

  for (const user of users) {
    const signUpTx = await userManager.methods.signUp(user.name, user.location, user.isDriver).send({ from: user.address, gas: 200000 });
    console.log(`User Signed Up - Name: ${user.name}, Address: ${user.address}, Gas Used: ${signUpTx.gasUsed}, Space Used: ${signUpTx.cumulativeGasUsed}`);
  }

  for (const driver of drivers) {
    const signUpTx = await userManager.methods.signUp(driver.name, driver.location, driver.isDriver).send({ from: driver.address, gas: 200000 });
    console.log(`Driver Signed Up - Name: ${driver.name}, Address: ${driver.address}, Gas Used: ${signUpTx.gasUsed}, Space Used: ${signUpTx.cumulativeGasUsed}`);
  }

  // Simulate ride requests
  const rideRequests = [];
  for (let i = 0; i < NUM_USERS; i++) {
    const request = {
      pickupLocation: generateRandomLocation(),
      dropOffLocation: generateRandomLocation(),
      fare: Math.floor(Math.random() * 20) + 5, // Random fare between 5 and 25
      zkProof: [Math.floor(Math.random() * 1000), Math.floor(Math.random() * 1000)],
      rider: `USER_ADDRESS_${i}`,
    };
    rideRequests.push(request);
  }

  for (const request of rideRequests) {
    const requestRideTx = await rideManager.methods
      .requestRide(request.pickupLocation, request.dropOffLocation, request.fare, request.zkProof)
      .send({ from: request.rider, gas: 300000 });
    console.log(`Ride Requested - Rider: ${request.rider}, Fare: ${request.fare}, Gas Used: ${requestRideTx.gasUsed}, Space Used: ${requestRideTx.cumulativeGasUsed}`);
  }

  // Simulate ride matching
  for (let i = 0; i < rideRequests.length; i++) {
    const matchRideTx = await rideManager.methods.matchRide(i).send({ from: drivers[i % NUM_DRIVERS].address, gas: 200000 });
    console.log(`Ride Matched - Rider: ${rideRequests[i].rider}, Driver: ${drivers[i % NUM_DRIVERS].address}, Gas Used: ${matchRideTx.gasUsed}, Space Used: ${matchRideTx.cumulativeGasUsed}`);
  }

  // Simulate ride completion
  for (let i = 0; i < rideRequests.length; i++) {
    const completeRideTx = await rideManager.methods.completeRide(i).send({ from: drivers[i % NUM_DRIVERS].address, gas: 200000 });
    console.log(`Ride Completed - Rider: ${rideRequests[i].rider}, Driver: ${drivers[i % NUM_DRIVERS].address}, Gas Used: ${completeRideTx.gasUsed}, Space Used: ${completeRideTx.cumulativeGasUsed}`);
  }
}

createUsersAndDrivers();
