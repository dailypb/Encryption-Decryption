import React, { useState, useEffect } from 'react';
import Web3 from 'web3';
import RideSharingContract from './contracts/RideSharingContract.json'; // Smart contract ABI

function DriverApp() {
    const [web3, setWeb3] = useState(null);
    const [contract, setContract] = useState(null);
    const [account, setAccount] = useState(null);

    useEffect(() => {
        const initWeb3 = async () => {
            if (window.ethereum) {
                const web3Instance = new Web3(window.ethereum);
                await window.ethereum.enable();
                setWeb3(web3Instance);

                const networkId = await web3Instance.eth.net.getId();
                const deployedNetwork = RideSharingContract.networks[networkId];
                const contractInstance = new web3Instance.eth.Contract(
                    RideSharingContract.abi,
                    deployedNetwork && deployedNetwork.address,
                );
                setContract(contractInstance);

                const accounts = await web3Instance.eth.getAccounts();
                setAccount(accounts[0]);
            }
        };

        initWeb3();
    }, []);

    return (
        <div>
            <h1>Driver Management App</h1>
            {web3 && contract && account && (
                <div>
                    <p>Connected Account: {account}</p>
                    {/* Write your driver management UI here */}
                </div>
            )}
        </div>
    );
}

export default DriverApp;
