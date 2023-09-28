package filters

import (
	"fmt"
	"strings"
	"log"
	"math"
	"math/big"
	"encoding/json"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
)

var client *ethclient.Client
var parsedABI_uniswapv2 abi.ABI
var parsedABI_ERC20 abi.ABI
var parsedABI_uniswapv3_multicall abi.ABI

func init() {
	var err error
	client, err = ethclient.Dial("http://localhost:8545")
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	parsedABI_uniswapv2, err = abi.JSON(strings.NewReader(ABI_UniswapV2))
	if err != nil {
		log.Fatalf("Failed to parse contract ABI: %v", err)
	}
	parsedABI_uniswapv3_multicall, err = abi.JSON(strings.NewReader(ABI_UniswapV3_Multicall))
	if err != nil {
		log.Fatalf("Failed to parse contract ABI: %v", err)
	}
	parsedABI_ERC20, err = abi.JSON(strings.NewReader(ABI_ERC20))
	if err != nil {
		log.Fatalf("Failed to parse contract ABI: %v", err)
	}
}

//  BEGIN UNISWAPV3 MULTICALL
// Structs for unmarshaling contract data
// These structs match the field names in the Ethereum contract
type TickData struct {
	Tick          *big.Int
	LiquidityNet  *big.Int
	LiquidityGross *big.Int
}

type ContractResponse struct {
	SqrtPriceX96  *big.Int
	Liquidity     *big.Int
	TickData      []TickData
}

// Structs for marshaling JSON response
// These structs use JSON field names used by ninja (python)
type Ticks struct {
	Tick           *big.Int `json:"tick"`
	LiquidityNet   *big.Int `json:"liquidityNet"`
	LiquidityGross *big.Int `json:"liquidityGross"`
}

type ResponseStruct_UniswapV3Multicall struct {
	SqrtPriceX96 *big.Int  `json:"sqrtPriceX96"`
	Liquidity    *big.Int  `json:"liquidity"`
	Ticks        []Ticks   `json:"ticks"`
}

func GetBalanceMetaData_UniswapV3(poolAddress string) (ResponseStruct_UniswapV3Multicall, error) {
	var metaData ResponseStruct_UniswapV3Multicall

	var multiCallAddress common.Address = common.HexToAddress("0x6560CEe7DC9C8498C3Fc81e214A99EE73E818870")
	instance_uniswapV3_multicall := bind.NewBoundContract(multiCallAddress, parsedABI_uniswapv3_multicall, client, client, client)

	var response []interface{}
	callOpts := &bind.CallOpts{}
	poolAddressConverted := common.HexToAddress(poolAddress)
	getNAdjacentTickWordsInBothDirections := uint16(20)
	err := instance_uniswapV3_multicall.Call(callOpts, &response, "getExchangePriceInputData", poolAddressConverted, getNAdjacentTickWordsInBothDirections)
	if err != nil {
		log.Println("GetBalanceMetaData_UniswapV3: Failed to retrieve value of variable:", err)
		return metaData, err
	}
	
	if len(response) == 0 {
		err = fmt.Errorf("response is empty")
		log.Println(err)
		return metaData, err
	}
	
	// Marshal the first item in the response into JSON bytes
	var contractResponse ContractResponse
	bytes, err := json.Marshal(response[0])
	if err != nil {
		log.Println("GetBalanceMetaData_UniswapV3: failed to marshal response[0]:", err)
		return metaData, err
	}
	
	// Unmarshal the JSON bytes into a ContractResponse struct
	err = json.Unmarshal(bytes, &contractResponse)
	if err != nil {
		log.Println("GetBalanceMetaData_UniswapV3: failed to unmarshal into ContractResponse:", err)
		return metaData, err
	}

	metaData.SqrtPriceX96 = contractResponse.SqrtPriceX96
	metaData.Liquidity = contractResponse.Liquidity

	for _, tickData := range contractResponse.TickData {
		ticks := Ticks{
			Tick: tickData.Tick,
			LiquidityNet: tickData.LiquidityNet,
			LiquidityGross: tickData.LiquidityGross,
		}
		metaData.Ticks = append(metaData.Ticks, ticks)
	}

	// Return the metadata as a ResponseStruct_UniswapV3Multicall struct
	return metaData, nil
}
//  END UNISWAPV3 MULTICALL

// TODO nick-smc i think i need to improve logging here
func GetBalanceMetaData_UniswapV2(poolAddress string) ([]float64, error) {
	var metaData []float64

	var contractAddress common.Address = common.HexToAddress(poolAddress)
	instance_uniswapV2 := bind.NewBoundContract(contractAddress, parsedABI_uniswapv2, client, client, client)

	// get reserves in wei
	var reserves []interface{}
	callOpts := &bind.CallOpts{}
	err := instance_uniswapV2.Call(callOpts, &reserves, "getReserves")
	if err != nil {
		fmt.Printf("Failed to retrieve value of variable: %v", err)
		return metaData, err
	}

	// get token0 address
	var token0Address []interface{}
	err = instance_uniswapV2.Call(callOpts, &token0Address, "token0")
	if err != nil {
		fmt.Printf("Failed to retrieve value of variable: %v", err)
		return metaData, err
	}

	// get token1 address
	var token1Address []interface{}
	err = instance_uniswapV2.Call(callOpts, &token1Address, "token1")
	if err != nil {
		fmt.Printf("Failed to retrieve value of variable: %v", err)
		return metaData, err
	}

	// get token0 decimals
	var token0Decimals []interface{}
	contractAddress = token0Address[0].(common.Address)
	instance_token0 := bind.NewBoundContract(contractAddress, parsedABI_uniswapv2, client, client, client)
	err = instance_token0.Call(callOpts, &token0Decimals, "decimals")
	if err != nil {
		fmt.Printf("Failed to retrieve value of variable: %v", err)
		return metaData, err
	}

	// get token1 decimals
	var token1Decimals []interface{}
	contractAddress = token1Address[0].(common.Address)
	instance_token1 := bind.NewBoundContract(contractAddress, parsedABI_uniswapv2, client, client, client)
	err = instance_token1.Call(callOpts, &token1Decimals, "decimals")
	if err != nil {
		fmt.Printf("Failed to retrieve value of variable: %v", err)
		return metaData, err
	}

	// convert reserves that are in wei units to ether units using the decimals
	reserves0_bigInt, ok := reserves[0].(*big.Int)
	if !ok {
		fmt.Printf("Failed to assert type: %v", err)
		return metaData, fmt.Errorf("Failed to assert type: %v", err)
	}
	token0Reserves := ConvertWeiUnitsToEtherUnits(reserves0_bigInt, token0Address[0].(common.Address).Hex())
	reserves1_bigInt, ok := reserves[1].(*big.Int)
	if !ok {
		fmt.Printf("Failed to assert type: %v", err)
		return metaData, fmt.Errorf("Failed to assert type: %v", err)
	}
	token1Reserves := ConvertWeiUnitsToEtherUnits(reserves1_bigInt, token1Address[0].(common.Address).Hex())

	metaData = append(metaData, token0Reserves)
	metaData = append(metaData, token1Reserves)

	return metaData, nil
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

	return tokenAmount_etherUnits
}
