package filters

import (
	"fmt"
	"strings"
	"log"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
)

var client *ethclient.Client
var parsedABI_uniswapv2 abi.ABI
var parsedABI_ERC20 abi.ABI

func init() {
	var err error
	client, err = ethclient.Dial("http://localhost:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	parsedABI_uniswapv2, err = abi.JSON(strings.NewReader(ABI_UniswapV2)) // contractABI is a string of the contract's ABI
	if err != nil {
		log.Fatalf("Failed to parse contract ABI: %v", err)
	}

	parsedABI_ERC20, err = abi.JSON(strings.NewReader(ABI_ERC20)) // contractABI is a string of the contract's ABI
	if err != nil {
		log.Fatalf("Failed to parse contract ABI: %v", err)
	}
}

// create a function called GetBalanceMetaData_UniswapV2 that returns an array of integers
// i want the function to return an array of floats
func GetBalanceMetaData_UniswapV2(poolAddress string) []float64 {
	// create an array of integers called metaData
	// TODO nick-smc maybe i only want float32 or another type here?
	var metaData []float64

	var contractAddress common.Address = common.HexToAddress(poolAddress)
	instance_uniswapV2 := bind.NewBoundContract(contractAddress, parsedABI_uniswapv2, client, client, client)

	// get reserves in wei
	var reserves []interface{}
	callOpts := &bind.CallOpts{}
	var err = instance_uniswapV2.Call(callOpts, &reserves, "getReserves")
	if err != nil {
		log.Fatalf("Failed to retrieve value of variable: %v", err)
	}
	if len(reserves) > 0 {
		fmt.Println("Reserves: ", reserves)
	}

	// get token0 address
	var token0Address []interface{}
	err = instance_uniswapV2.Call(callOpts, &token0Address, "token0")
	if err != nil {
		log.Fatalf("Failed to retrieve value of variable: %v", err)
	}

	// get token1 address
	var token1Address []interface{}
	err = instance_uniswapV2.Call(callOpts, &token1Address, "token1")
	if err != nil {
		log.Fatalf("Failed to retrieve value of variable: %v", err)
	}

	// get token0 decimals
	var token0Decimals []interface{}
	contractAddress = token0Address[0].(common.Address)
	instance_token0 := bind.NewBoundContract(contractAddress, parsedABI_uniswapv2, client, client, client)
	err = instance_token0.Call(callOpts, &token0Decimals, "decimals")
	if err != nil {
		log.Fatalf("Failed to retrieve value of variable: %v", err)
	}

	// get token1 decimals
	var token1Decimals []interface{}
	contractAddress = token1Address[0].(common.Address)
	instance_token1 := bind.NewBoundContract(contractAddress, parsedABI_uniswapv2, client, client, client)
	err = instance_token1.Call(callOpts, &token1Decimals, "decimals")
	if err != nil {
		log.Fatalf("Failed to retrieve value of variable: %v", err)
	}

	// convert reserves that are in wei units to ether units using the decimals
	reserves0_bigInt, ok := reserves[0].(*big.Int)
	if !ok {
		log.Fatalf("Failed to assert type: %v", err)
	}
	token0Reserves := ConvertWeiUnitsToEtherUnits(reserves0_bigInt, token0Address[0].(common.Address).Hex())
	reserves1_bigInt, ok := reserves[0].(*big.Int)
	if !ok {
		log.Fatalf("Failed to assert type: %v", err)
	}
	token1Reserves := ConvertWeiUnitsToEtherUnits(reserves1_bigInt, token1Address[0].(common.Address).Hex())

	// append the token0Reserves and token1Reserves to the metaData array
	metaData = append(metaData, token0Reserves)
	metaData = append(metaData, token1Reserves)
	
	return metaData
}

// create a function that takes in tokemAmount as a bigInt and token address and returns the balance in ether units
func ConvertWeiUnitsToEtherUnits(tokenAmount *big.Int, tokenAddress string) float64 {
	var contractAddress common.Address = common.HexToAddress(tokenAddress)
	instance_ERC20 := bind.NewBoundContract(contractAddress, parsedABI_ERC20, client, client, client)

	// get token decimals
	var tokenDecimals []interface{}
	callOpts := &bind.CallOpts{}
	err := instance_ERC20.Call(callOpts, &tokenDecimals, "decimals")
	if err != nil {
		log.Fatalf("Failed to retrieve value of variable: %v", err)
	}

	// convert tokenAmount that are in wei units to ether units using the decimals
	tokenDecimals_float64 := float64(tokenDecimals[0].(uint8))
	tokenAmount_float64 := new(big.Float).SetInt(tokenAmount)
	tokenAmount_etherUnits, _ := new(big.Float).Quo(tokenAmount_float64, new(big.Float).Mul(big.NewFloat(math.Pow(10.0, tokenDecimals_float64)), big.NewFloat(1))).Float64()
	fmt.Println("Token amount in ether units: ", tokenAmount_etherUnits)

	return tokenAmount_etherUnits
}
