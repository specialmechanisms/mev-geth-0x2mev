package filters

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

var client *ethclient.Client
var parsedABI_uniswapv2 abi.ABI
var parsedABI_ERC20 abi.ABI
var parsedABI_uniswapv3_multicall abi.ABI
var parsedABI_uniswapv3_pool abi.ABI
var parsedABI_balancerv2_vault abi.ABI
var parsedABI_balancerv2_pool abi.ABI

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
	parsedABI_uniswapv3_pool, err = abi.JSON(strings.NewReader(ABI_UniswapV3_Pool))
	if err != nil {
		log.Fatalf("Failed to parse contract ABI: %v", err)
	}
	parsedABI_balancerv2_vault, err = abi.JSON(strings.NewReader(ABI_BalancerV2_Vault))
	if err != nil {
		log.Fatalf("Failed to parse contract ABI: %v", err)
	}
	parsedABI_balancerv2_pool, err = abi.JSON(strings.NewReader(ABI_BalancerV2_WeightedPool))
	if err != nil {
		log.Fatalf("Failed to parse contract ABI: %v", err)
	}
	parsedABI_ERC20, err = abi.JSON(strings.NewReader(ABI_ERC20))
	if err != nil {
		log.Fatalf("Failed to parse contract ABI: %v", err)
	}
}

type MetaData_BalancerV2 struct {
	Address        string
	Tokens         []string
	Balances       []float64
	Fee            float64
	ScalingFactors []*big.Int
}

func GetBalanceMetaData_BalancerV2(poolId common.Hash) (MetaData_BalancerV2, common.Address, error) {
	// the event gets fired on the vault contract and not on the pool.
	// we will get the poolAddress from the poolId and return the poolAddres the address of PoolBalanceMetaData struct outside this function can get updated
	var metaData MetaData_BalancerV2

	var vaultAddress common.Address = common.HexToAddress("0xBA12222222228d8Ba445958a75a0704d566BF2C8")
	instance_balancerv2_vault := bind.NewBoundContract(vaultAddress, parsedABI_balancerv2_vault, client, client, client)

	poolAddress := common.BytesToAddress(poolId.Bytes()[:20])
	metaData.Address = poolAddress.Hex()
	instance_balancerv2_weightedPool := bind.NewBoundContract(poolAddress, parsedABI_balancerv2_pool, client, client, client)

	// TODO nick-smc check the vault of the pool to make sure it is a balancer pool (like in the uniswapv3 function)

	// we need to do 3 calls
	// 1. getPoolTokens -> on vault
	// 2. getPoolFees -> on the pool
	// 3. getPoolScalingFactors -> on the pool, but sometimes there is no scaling factors, so we need to handle that case

	// 1. getPoolTokens
	var tokensAndBalances []interface{}
	callOpts := &bind.CallOpts{}
	err := instance_balancerv2_vault.Call(callOpts, &tokensAndBalances, "getPoolTokens", poolId)
	if err != nil {
		log.Println("GetBalanceMetaData_BalancerV2: Failed to retrieve value of variable:", err)
		return metaData, poolAddress, err
	}
	addresses := tokensAndBalances[0].([]common.Address)
	balances := tokensAndBalances[1].([]*big.Int)

	for i := 0; i < len(addresses); i++ {
		token := addresses[i].Hex()
		metaData.Tokens = append(metaData.Tokens, token)
		balance_wei := balances[i]
		balance_ether := ConvertWeiUnitsToEtherUnits(balance_wei, token)
		metaData.Balances = append(metaData.Balances, balance_ether)
	}

	// 2. getSwapFeePercentage
	var poolFee []interface{}
	err = instance_balancerv2_weightedPool.Call(callOpts, &poolFee, "getSwapFeePercentage")
	if err != nil {
		log.Println("GetBalanceMetaData_BalancerV2: Failed to retrieve value of variable:", err)
		return metaData, poolAddress, err
	}
	fee_bigInt := poolFee[0].(*big.Int)
	// divide fee_bigInt by 1e18. i just use WETH contract here because it has 18 decimals 
	metaData.Fee = ConvertWeiUnitsToEtherUnits(fee_bigInt, "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")

	// // 3. getPoolScalingFactors
	var poolScalingFactors []interface{}
	err = instance_balancerv2_weightedPool.Call(callOpts, &poolScalingFactors, "getScalingFactors")
	if err != nil {
		if strings.Contains(err.Error(), "execution reverted") {
			log.Println("The above execution reverted warning can be ignored. it is handled in the code and expected to happen.")
			// The getScalingFactors function doesn't exist for this pool.
			// Continue without logging an error.
			metaData.ScalingFactors = nil // Explicitly set ScalingFactors to nil
		} else {
			// An unexpected error occurred.
			log.Println("GetBalanceMetaData_BalancerV2: Failed to retrieve value of variable:", err)
			return metaData, poolAddress, err
		}
	} else {
		metaData.ScalingFactors = poolScalingFactors[0].([]*big.Int)
	}

	return metaData, poolAddress, nil
}

//	BEGIN UNISWAPV3 MULTICALL
//
// Structs for unmarshaling contract data
// These structs match the field names in the Ethereum contract
type TickData struct {
	Tick           *big.Int
	LiquidityNet   *big.Int
	LiquidityGross *big.Int
}

type ContractResponse struct {
	SqrtPriceX96 *big.Int
	Liquidity    *big.Int
	TickData     []TickData
}

// Structs for marshaling JSON response
// These structs use JSON field names used by ninja (python)
type Ticks struct {
	Tick           *big.Int `json:"tick"`
	LiquidityNet   *big.Int `json:"liquidityNet"`
	LiquidityGross *big.Int `json:"liquidityGross"`
}

type ResponseStruct_UniswapV3Multicall struct {
	SqrtPriceX96 *big.Int `json:"sqrtPriceX96"`
	Liquidity    *big.Int `json:"liquidity"`
	Ticks        []Ticks  `json:"ticks"`
}

func GetBalanceMetaData_UniswapV3(poolAddress string) (ResponseStruct_UniswapV3Multicall, error) {
	var metaData ResponseStruct_UniswapV3Multicall

	var multiCallAddress common.Address = common.HexToAddress("0x6560CEe7DC9C8498C3Fc81e214A99EE73E818870")
	instance_uniswapV3_multicall := bind.NewBoundContract(multiCallAddress, parsedABI_uniswapv3_multicall, client, client, client)

	// The response_factoryCall is a pointer to a common.Address that will store the address returned by the factory function of the UniswapV3 pool contract.
	// The responseSlice is a slice of interface{} that holds a pointer to response_factoryCall, and it’s used because the Call function expects its second argument
	//  to be a pointer to a slice of interface{}, where it will store the returned values from the contract call.
	response_factoryCall := new(common.Address)
	var responseSlice []interface{} = make([]interface{}, 1)
	responseSlice[0] = &response_factoryCall
	callOpts := &bind.CallOpts{}
	poolAddressConverted := common.HexToAddress(poolAddress)
	instance_uniswapV3_pool := bind.NewBoundContract(poolAddressConverted, parsedABI_uniswapv3_pool, client, client, client)

	// get the factory address of the pool - this way we can check if it is a uniswapv3 pool or some obscure clone
	err := instance_uniswapV3_pool.Call(callOpts, &responseSlice, "factory")
	if err != nil {
		return metaData, err
	}

	uniswapV3FactoryAddress := "0x1F98431c8aD98523631AE4a59f267346ea31F984"
	poolFactoryAddress := response_factoryCall.Hex()
	if poolFactoryAddress != uniswapV3FactoryAddress {
		err = fmt.Errorf("poolAddress is not a uniswapV3 pool")
		log.Println(err)
		return metaData, err
	}

	var response []interface{}
	getNAdjacentTickWordsInBothDirections := uint16(20)
	err = instance_uniswapV3_multicall.Call(callOpts, &response, "getExchangePriceInputData", poolAddressConverted, getNAdjacentTickWordsInBothDirections)
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
			Tick:           tickData.Tick,
			LiquidityNet:   tickData.LiquidityNet,
			LiquidityGross: tickData.LiquidityGross,
		}
		metaData.Ticks = append(metaData.Ticks, ticks)
	}

	return metaData, nil
}

//  END UNISWAPV3 MULTICALL

// TODO nick-smc i think i need to improve logging here
func GetBalanceMetaData_UniswapV2(poolAddress string) ([]float64, error) {
	var metaData []float64

	var contractAddress common.Address = common.HexToAddress(poolAddress)
	instance_uniswapV2 := bind.NewBoundContract(contractAddress, parsedABI_uniswapv2, client, client, client)

	// TODO nick-smc you can check the factory of the pool to make sure it is a uniswapv2 pool (like in the uniswapv3 function)
	// TODO nick-smc that way we can even find out if it is a uniswapv2 or sushiswap pool etc.
	// --> get the factory address from the router contract and compare it to the factory address of the pool.
	// you want to init all the factory contracts in the init function and then use them here
	// you can then return the right exchange name and override it outside of the function

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
