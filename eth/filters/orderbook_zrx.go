package filters

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	// "time"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"strconv"
)

// TODO nick clean up the file

var (
	ORDERBOOKNAME_ZRX = "zrx"
)

type ZRXOrder struct {
	Order
	OffChainData ZRXOffChainData
	OnChainData  ZRXOnChainData
}

type ZRXOrderRaw struct {
	Order
	OffChainData ZRXOffChainDataRaw
	OnChainData  ZRXOnChainData
}

// Raw structs are used to unmarshal data from the stream and convert it to the required format for contract calls.
type ZRXOffChainDataRaw struct {
	Order    ZRXOrderDetailsRaw `json:"order"`
	MetaData ZRXMetaData        `json:"metaData"`
}

type ZRXOrderDetailsRaw struct {
	Signature           ZRXSignatureRaw `json:"signature"`
	Sender              string          `json:"sender"`
	Maker               string          `json:"maker"`
	Taker               string          `json:"taker"`
	TakerTokenFeeAmount string          `json:"takerTokenFeeAmount"`
	MakerAmount         string          `json:"makerAmount"`
	TakerAmount         string          `json:"takerAmount"`
	MakerToken          string          `json:"makerToken"`
	TakerToken          string          `json:"takerToken"`
	Salt                string          `json:"salt"`
	VerifyingContract   string          `json:"verifyingContract"`
	FeeRecipient        string          `json:"feeRecipient"`
	Expiry              string          `json:"expiry"`
	ChainID             string          `json:"chainId"`
	Pool                string          `json:"pool"`
}

type ZRXOffChainData struct {
	Order    ZRXOrderDetails `json:"order"`
	MetaData ZRXMetaData     `json:"metaData"`
}

type ZRXSignatureRaw struct {
	SignatureType string `json:"signatureType"`
	R             string `json:"r"`
	S             string `json:"s"`
	V             string `json:"v"`
}

type ZRXSignature struct {
	SignatureType int    `json:"signatureType"`
	R             string `json:"r"`
	S             string `json:"s"`
	V             int    `json:"v"`
}

type ZRXMetaData struct {
	OrderHash                    string `json:"orderHash"`
	RemainingFillableTakerAmount string `json:"remainingFillableTakerAmount"`
	CreatedAt                    string `json:"createdAt"`
}

// TODO nick-0x make those strings into common.Address
type ZRXOrderDetails struct {
	Signature           ZRXSignature `json:"signature"`
	Sender              string       `json:"sender"`
	Maker               string       `json:"maker"`
	Taker               string       `json:"taker"`
	TakerTokenFeeAmount *big.Int     `json:"takerTokenFeeAmount"`
	MakerAmount         *big.Int     `json:"makerAmount"`
	TakerAmount         *big.Int     `json:"takerAmount"`
	MakerToken          string       `json:"makerToken"`
	TakerToken          string       `json:"takerToken"`
	Salt                *big.Int     `json:"salt"`
	VerifyingContract   string       `json:"verifyingContract"`
	FeeRecipient        string       `json:"feeRecipient"`
	Expiry              uint64       `json:"expiry"`
	ChainID             int          `json:"chainId"`
	Pool                [32]byte     `json:"pool"`
}

type ZRXOnChainData struct {
	MakerBalance_weiUnits   *big.Int     `json:"makerBalance_weiUnits"`
	MakerAllowance_weiUnits *big.Int     `json:"makerAllowance_weiUnits"`
	OrderInfo               ZRXOrderInfo `json:"orderInfo"`
}

type ZRXOrderInfo struct {
	// OrderHash               [32]byte `json:"orderHash"`
	Status                 int      `json:"status"`
	TakerTokenFilledAmount *big.Int `json:"takerTokenFilledAmount"`
}

// MarshalJSON implements the json.Marshaler interface for ZRXOnChainData
func (o ZRXOnChainData) MarshalJSON() ([]byte, error) {
	type Alias ZRXOnChainData
	return json.Marshal(&struct {
		MakerBalance_weiUnits   string `json:"makerBalance_weiUnits"`
		MakerAllowance_weiUnits string `json:"makerAllowance_weiUnits"`
		*Alias
	}{
		MakerBalance_weiUnits:   o.MakerBalance_weiUnits.String(),
		MakerAllowance_weiUnits: o.MakerAllowance_weiUnits.String(),
		Alias:                   (*Alias)(&o),
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface for ZRXOnChainData
func (o *ZRXOnChainData) UnmarshalJSON(data []byte) error {
	type Alias ZRXOnChainData
	aux := &struct {
		MakerBalance_weiUnits   string `json:"makerBalance_weiUnits"`
		MakerAllowance_weiUnits string `json:"makerAllowance_weiUnits"`
		*Alias
	}{
		Alias: (*Alias)(o),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	var ok bool
	o.MakerBalance_weiUnits, ok = new(big.Int).SetString(aux.MakerBalance_weiUnits, 10)
	if !ok {
		return fmt.Errorf("failed to parse MakerBalance_weiUnits")
	}
	o.MakerAllowance_weiUnits, ok = new(big.Int).SetString(aux.MakerAllowance_weiUnits, 10)
	if !ok {
		return fmt.Errorf("failed to parse MakerAllowance_weiUnits")
	}
	return nil
}

// MarshalJSON implements the json.Marshaler interface for ZRXOrderInfo
func (o ZRXOrderInfo) MarshalJSON() ([]byte, error) {
	type Alias ZRXOrderInfo
	return json.Marshal(&struct {
		TakerTokenFilledAmount string `json:"takerTokenFilledAmount"`
		*Alias
	}{
		TakerTokenFilledAmount: o.TakerTokenFilledAmount.String(),
		Alias:                  (*Alias)(&o),
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface for ZRXOrderInfo
func (o *ZRXOrderInfo) UnmarshalJSON(data []byte) error {
	type Alias ZRXOrderInfo
	aux := &struct {
		TakerTokenFilledAmount string `json:"takerTokenFilledAmount"`
		*Alias
	}{
		Alias: (*Alias)(o),
	}
	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}
	var ok bool
	o.TakerTokenFilledAmount, ok = new(big.Int).SetString(aux.TakerTokenFilledAmount, 10)
	if !ok {
		return fmt.Errorf("failed to parse TakerTokenFilledAmount")
	}
	return nil
}

func CreateZRXOffChainData(rawData ZRXOffChainDataRaw) (ZRXOffChainData, error) {
	log.Println("CreateZRXOffChainData: rawData", rawData)
	log.Println("CreateZRXOffChainData: rawData.Order", rawData.Order)
	log.Println("CreateZRXOffChainData: rawData.Order.TakerTokenFeeAmount", rawData.Order.TakerTokenFeeAmount)
	takerTokenFeeAmount, ok := new(big.Int).SetString(rawData.Order.TakerTokenFeeAmount, 10)
	if !ok {
		return ZRXOffChainData{}, fmt.Errorf("failed to convert TakerTokenFeeAmount")
	}
	makerAmount, ok := new(big.Int).SetString(rawData.Order.MakerAmount, 10)
	if !ok {
		return ZRXOffChainData{}, fmt.Errorf("failed to convert MakerAmount")
	}
	takerAmount, ok := new(big.Int).SetString(rawData.Order.TakerAmount, 10)
	if !ok {
		return ZRXOffChainData{}, fmt.Errorf("failed to convert TakerAmount")
	}
	salt, ok := new(big.Int).SetString(rawData.Order.Salt, 10)
	if !ok {
		return ZRXOffChainData{}, fmt.Errorf("failed to convert Salt")
	}
	expiry, err := strconv.ParseUint(rawData.Order.Expiry, 10, 64)
	if err != nil {
		return ZRXOffChainData{}, fmt.Errorf("failed to convert Expiry")
	}
	pool := common.HexToHash(rawData.Order.Pool)

	chainID, err := strconv.Atoi(rawData.Order.ChainID)
	if err != nil {
		return ZRXOffChainData{}, fmt.Errorf("failed to convert ChainID")
	}

	signature, err := CreateZRXSignature(rawData.Order.Signature)
	if err != nil {
		return ZRXOffChainData{}, fmt.Errorf("failed to create ZRXSignature: %v", err)
	}

	return ZRXOffChainData{
		Order: ZRXOrderDetails{
			Signature:           signature,
			Sender:              rawData.Order.Sender,
			Maker:               rawData.Order.Maker,
			Taker:               rawData.Order.Taker,
			TakerTokenFeeAmount: takerTokenFeeAmount,
			MakerAmount:         makerAmount,
			TakerAmount:         takerAmount,
			MakerToken:          rawData.Order.MakerToken,
			TakerToken:          rawData.Order.TakerToken,
			Salt:                salt,
			VerifyingContract:   rawData.Order.VerifyingContract,
			FeeRecipient:        rawData.Order.FeeRecipient,
			Expiry:              expiry,
			ChainID:             chainID,
			Pool:                pool,
		},
		MetaData: rawData.MetaData,
	}, nil
}

func CreateZRXSignature(rawData ZRXSignatureRaw) (ZRXSignature, error) {
	signatureType, err := strconv.Atoi(rawData.SignatureType)
	if err != nil {
		return ZRXSignature{}, fmt.Errorf("failed to convert SignatureType")
	}
	v, err := strconv.Atoi(rawData.V)
	if err != nil {
		return ZRXSignature{}, fmt.Errorf("failed to convert V")
	}

	return ZRXSignature{
		SignatureType: signatureType,
		R:             rawData.R,
		S:             rawData.S,
		V:             v,
	}, nil
}

func ZRXConvertOrderToZRXOrder(order Order) (ZRXOrder, error) {
	zrxOrderRaw, err := ZRXConvertOrderToZRXOrderRaw(order)
	if err != nil {
		return ZRXOrder{}, fmt.Errorf("failed to convert order to ZRXOrderRaw: %v", err)
	}
	zrxOrder, err := ZRXConvertZRXOrderRawToZRXOrder(zrxOrderRaw)
	if err != nil {
		return ZRXOrder{}, fmt.Errorf("failed to convert ZRXOrderRaw to ZRXOrder: %v", err)
	}
	return zrxOrder, nil
}

func ConvertOffChainDataToZRXOffChainDataRaw(offChainData interface{}) (ZRXOffChainDataRaw, error) {
	data, ok := offChainData.(ZRXOffChainDataRaw)
	if !ok {
		return ZRXOffChainDataRaw{}, fmt.Errorf("failed to convert OffChainData to ZRXOffChainDataRaw")
	}
	return data, nil
}

func ZRXConvertOrderToZRXOrderRaw(order Order) (ZRXOrderRaw, error) {
	var zrxOrderRaw ZRXOrderRaw
	zrxOrderRaw.Order = order

	// Attempt to assert OffChainData to ZRXOffChainDataRaw
	log.Println("ZRXConvertOrderToZRXOrderRaw: order.OffChainData", order.OffChainData)
	offChainData, ok := order.OffChainData.(ZRXOffChainDataRaw)
	if !ok {
		// Attempt to manually unmarshal OffChainData
		data, err := json.Marshal(order.OffChainData)
		if err != nil {
			return zrxOrderRaw, fmt.Errorf("failed to marshal OffChainData: %v", err)
		}
		var zrxOffChainDataRaw ZRXOffChainDataRaw
		err = json.Unmarshal(data, &zrxOffChainDataRaw)
		if err != nil {
			return zrxOrderRaw, fmt.Errorf("failed to unmarshal OffChainData to ZRXOffChainDataRaw: %v", err)
		}
		offChainData = zrxOffChainDataRaw
	}
	zrxOrderRaw.OffChainData = offChainData

	return zrxOrderRaw, nil
}

// func ZRXConvertZRXOrderRawToOrder(zrxOrderRaw ZRXOrderRaw) Order {
//     return Order{
//         OrderHash:     zrxOrderRaw.OrderHash,
//         OrderBookName: zrxOrderRaw.OrderBookName,
//         OffChainData:  zrxOrderRaw.OffChainData,
//         OnChainData: OnChainData{
//             MakerBalance_weiUnits:   zrxOrderRaw.OnChainData.MakerBalance_weiUnits,
//             MakerAllowance_weiUnits: zrxOrderRaw.OnChainData.MakerAllowance_weiUnits,
//             OrderInfo: ZRXOrderInfo{
//                 Status:                 zrxOrderRaw.OnChainData.OrderInfo.Status,
//                 TakerTokenFilledAmount: zrxOrderRaw.OnChainData.OrderInfo.TakerTokenFilledAmount,
//             },
//         },
//     }
// }

func ZRXConvertZRXOrderRawToZRXOrder(zrxOrder ZRXOrderRaw) (ZRXOrder, error) {
	var convertedOrder ZRXOrder
	convertedOrder.Order = zrxOrder.Order

	// Convert ZRXOffChainDataRaw to ZRXOffChainData
	offChainDataRaw := zrxOrder.OffChainData
	offChainData, err := CreateZRXOffChainData(offChainDataRaw)
	if err != nil {
		return convertedOrder, fmt.Errorf("failed to convert ZRXOffChainDataRaw to ZRXOffChainData: %v", err)
	}
	convertedOrder.OffChainData = offChainData

	return convertedOrder, nil
}

func ZRXGetOnChainData(order ZRXOrder) (OnChainData, error) {
	var onChainData OnChainData

	// order, err = ZRXConvertOrderToZRXOrder(order)
	if err != nil {
		return onChainData, fmt.Errorf("failed to convert order to ZRXOrder: %v", err)
	}

	// Log the type of OffChainData
	log.Printf("ZRXGetOnChainData: OffChainData type: %T", order.OffChainData)

	// // Attempt to assert OffChainData to ZRXOffChainData
	// offChainData, ok := order.ZRXOffChainData.(ZRXOffChainData)
	// if !ok {
	//     // Log the actual content of OffChainData
	//     log.Printf("ZRXGetOnChainData: OffChainData content: %+v", order.OffChainData)
	// }

	// Log the maker address
	log.Println("ZRXGetOnChainData: maker address", order.OffChainData.Order.Maker)
	log.Println("ZRXGetOnChainData: maker token", order.OffChainData.Order.MakerToken)
	// Retrieve the MakerBalance_weiUnits (maker's makerToken balance)
	// Assuming you have a function to get the balance
	makerBalance_weiUnits, err := GetERC20TokenBalance(
		common.HexToAddress(order.OffChainData.Order.Maker),
		common.HexToAddress(order.OffChainData.Order.MakerToken))
	if err != nil {
		return onChainData, fmt.Errorf("failed to get maker balance: %v", err)
	}
	onChainData.MakerBalance_weiUnits = makerBalance_weiUnits

	// Retrieve the MakerAllowance_weiUnits (maker's allowance)
	// Assuming you have a function to get the allowance
	makerAllowance_weiUnits, err := GetERC20TokenAllowance(
		common.HexToAddress(order.OffChainData.Order.MakerToken),
		common.HexToAddress(order.OffChainData.Order.Maker),
		common.HexToAddress(order.OffChainData.Order.VerifyingContract))
	if err != nil {
		return onChainData, fmt.Errorf("failed to get maker allowance: %v", err)
	}
	onChainData.MakerAllowance_weiUnits = makerAllowance_weiUnits

	// Retrueve the OrderInfo from the verifying contract
	orderInfo, err := ZRXGetOrderInfo(order)
	if err != nil {
		return onChainData, fmt.Errorf("failed to get order info: %v", err)
	}
	log.Println("ZRXGetOnChainData: orderInfo", orderInfo)

	onChainData.OrderInfo = orderInfo

	// Log the retrieved on-chain data
	log.Printf("ZRXGetOnChainData: Retrieved on-chain data: %+v", onChainData)

	return onChainData, nil
}

func ZRXGetOrderInfo(order ZRXOrder) (ZRXOrderInfo, error) {
	log.Println("ZRXGetOrderInfo: order", order)
	log.Println("ZRXGetOrderInfo: order.OrderHash", order.OrderHash)

	// get the verifying contract which is inside of ZRXOrderDetails
	var orderInfoResponse []interface{}
	var contractAddress common.Address = common.HexToAddress(order.OffChainData.Order.VerifyingContract)
	instance_zrxExchangeProxy := bind.NewBoundContract(contractAddress, parsedABI_ZRXV4, client, client, client)

	log.Println("ZRXGetOrderInfo: verifying contract", order.OffChainData.Order.VerifyingContract)

	// Define the input parameters as a struct
	inputParameters := struct {
		MakerToken          common.Address
		TakerToken          common.Address
		MakerAmount         *big.Int
		TakerAmount         *big.Int
		TakerTokenFeeAmount *big.Int
		Maker               common.Address
		Taker               common.Address
		Sender              common.Address
		FeeRecipient        common.Address
		Pool                [32]byte
		Expiry              uint64
		Salt                *big.Int
	}{
		MakerToken:          common.HexToAddress(order.OffChainData.Order.MakerToken),
		TakerToken:          common.HexToAddress(order.OffChainData.Order.TakerToken),
		MakerAmount:         order.OffChainData.Order.MakerAmount,
		TakerAmount:         order.OffChainData.Order.TakerAmount,
		TakerTokenFeeAmount: order.OffChainData.Order.TakerTokenFeeAmount,
		Maker:               common.HexToAddress(order.OffChainData.Order.Maker),
		Taker:               common.HexToAddress(order.OffChainData.Order.Taker),
		Sender:              common.HexToAddress(order.OffChainData.Order.Sender),
		FeeRecipient:        common.HexToAddress(order.OffChainData.Order.FeeRecipient),
		Pool:                order.OffChainData.Order.Pool,
		Expiry:              order.OffChainData.Order.Expiry,
		Salt:                order.OffChainData.Order.Salt,
	}

	// Call the getLimitOrderInfo function on the contract
	callOpts := &bind.CallOpts{}
	err := instance_zrxExchangeProxy.Call(callOpts, &orderInfoResponse, "getLimitOrderInfo", inputParameters)
	if err != nil {
		log.Println("ZRXGetOrderInfo: failed to get order info: ", err)
		return ZRXOrderInfo{}, err
	}
	log.Println("ZRXGetOrderInfo: orderInfoResponse", orderInfoResponse)

	// Assert the response to the expected struct
	orderInfo := orderInfoResponse[0].(struct {
		OrderHash              [32]byte `json:"orderHash"`
		Status                 uint8    `json:"status"`
		TakerTokenFilledAmount *big.Int `json:"takerTokenFilledAmount"`
	})

	return ZRXOrderInfo{
		// OrderHash:              orderInfo.OrderHash,
		Status:                 int(orderInfo.Status),
		TakerTokenFilledAmount: orderInfo.TakerTokenFilledAmount,
	}, nil
}

func ConvertZRXOrderToMap(order Order) map[string]interface{} {
	orderMap := make(map[string]interface{})
	orderMap["orderHash"] = order.OrderHash
	orderMap["orderBookName"] = order.OrderBookName

	// Marshal OffChainData to JSON string
	offChainDataJSON, err := json.Marshal(order.OffChainData)
	if err != nil {
		log.Fatalf("Failed to marshal OffChainData: %v", err)
	}
	orderMap["offChainData"] = string(offChainDataJSON)

	// Marshal OnChainData to JSON string
	onChainDataJSON, err := json.Marshal(order.OnChainData)
	if err != nil {
		log.Fatalf("Failed to marshal OnChainData: %v", err)
	}
	orderMap["onChainData"] = string(onChainDataJSON)

	return orderMap
}

func GetBalanceMetaData_ERC20_Transfer(tokenAddress common.Address, eventLog *Log) (MetaData_ERC20Balances, error) {
	var result MetaData_ERC20Balances
	log.Println("found erc20 transfer event")
	// event Transfer(address indexed src, address indexed dst, uint wad);
	// src is the sender, dst is the receiver, wad is the amount in wei

	// make sure the event log has a length of at least 3
	if len(eventLog.Topics) != 3 {
		return result, fmt.Errorf("event log does not have the correct number of topics. token:", tokenAddress)
	}

	senderAddress := common.HexToAddress(eventLog.Topics[1].Hex())
	receiverAddress := common.HexToAddress(eventLog.Topics[2].Hex())
	log.Println("senderAddress", senderAddress)
	log.Println("receiverAddress", receiverAddress)

	senderBalance_weiUnits, err := GetERC20TokenBalance(senderAddress, tokenAddress)
	if err != nil {
		return result, fmt.Errorf("failed to get balance: %v", err)
	}
	log.Println("senderBalance_weiUnits", senderBalance_weiUnits)
	receiverBalance_weiUnits, err := GetERC20TokenBalance(receiverAddress, tokenAddress)
	if err != nil {
		return result, fmt.Errorf("failed to get balance: %v", err)
	}
	log.Println("receiverBalance_weiUnits", receiverBalance_weiUnits)

	senderBalance_etherUnits, err := ConvertWeiUnitsToEtherUnits_UsingTokenAddress(
		senderBalance_weiUnits, tokenAddress.Hex())
	if err != nil {
		return result, fmt.Errorf("failed to convert balance to ether units: %v", err)
	}
	log.Println("receiverBalance_etherUnits", senderBalance_etherUnits)
	receiverBalance_etherUnits, err := ConvertWeiUnitsToEtherUnits_UsingTokenAddress(
		receiverBalance_weiUnits, tokenAddress.Hex())
	if err != nil {
		return result, fmt.Errorf("failed to convert balance to ether units: %v", err)
	}
	log.Println("receiverBalance_etherUnits", receiverBalance_etherUnits)

	result = MetaData_ERC20Balances{
		SenderAddress:              senderAddress,
		SenderBalance_etherUnits:   senderBalance_etherUnits,
		ReceiverAddress:            receiverAddress,
		ReceiverBalance_etherUnits: receiverBalance_etherUnits,
	}
	log.Println("result", result)
	return result, nil
}

func GetBalanceMetaData_ERC20_Allowance(tokenAddress common.Address, eventLog *Log) (MetaData_ERC20Allowance, error) {
	log.Println("found erc20 allowance event")
	// emit Approval(msg.sender, usr, wad);
	var result MetaData_ERC20Allowance
	// we do not need to make a call because everything is already in the event log

	// make sure the event log has a length of at least 3
	if len(eventLog.Topics) != 3 {
		return result, fmt.Errorf("event log does not have the correct number of topics. token:", tokenAddress)
	}

	log.Println("tokenAddress", tokenAddress)
	log.Println("eventLog", eventLog)
	ownerAddress := common.HexToAddress(eventLog.Topics[1].Hex())
	spenderAddress := common.HexToAddress(eventLog.Topics[2].Hex())
	amount_weiUnits := new(big.Int).SetBytes(eventLog.Data)
	log.Println("ownerAddress", ownerAddress)
	log.Println("spenderAddress", spenderAddress)
	log.Println("amount_weiUnits", amount_weiUnits)
	// // make sure addresses are right length
	// if len(ownerAddress) != 42 || len(spenderAddress) != 42 {
	//     return result, fmt.Errorf("owner or spender address is not the correct length")
	// }
	amount_etherUnits, err := ConvertWeiUnitsToEtherUnits_UsingTokenAddress(
		amount_weiUnits, tokenAddress.Hex())
	if err != nil {
		return result, fmt.Errorf("failed to convert allowance to ether units: %v", err)
	}
	log.Println("amount_etherUnits", amount_etherUnits)
	result = MetaData_ERC20Allowance{
		OwnerAddress:      ownerAddress,
		SpenderAddress:    spenderAddress,
		Amount_etherUnits: amount_etherUnits,
	}
	log.Println("result", result)
	return result, nil
}

func GetBalanceMetaData_ERC20(tokenAddress common.Address, eventLog *Log) (interface{}, error) {
	// Get the balance of the token

	// make sure the event log has a length of at least 3
	if len(eventLog.Topics) != 3 {
		return nil, fmt.Errorf("event log does not have the correct number of topics. token:", tokenAddress)
	}

	// call the decimals function of the token to make increase the chance of the token to be a valid ERC20 token
	_, err := GetTokenDecimals(tokenAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get token decimals for tokenAddress: %v", tokenAddress)
	}

	switch eventLog.Topics[0].Hex() {
	case topic_erc20Transfer:
		return GetBalanceMetaData_ERC20_Transfer(tokenAddress, eventLog)
	case topic_erc20Allowance:
		return GetBalanceMetaData_ERC20_Allowance(tokenAddress, eventLog)
	default:
		return "", fmt.Errorf("failed to get balance meta data for ERC20 event log")
	}
}

func GetTokenDecimals(tokenAddress common.Address) (int, error) {
	// get token decimals
	var tokenDecimals []interface{}

	for _, knownAddress := range KnownEthereumAddresses {
		if tokenAddress.Hex() == knownAddress {
			return 18, nil
		}
	}

	instance_token := bind.NewBoundContract(tokenAddress, parsedABI_ERC20, client, client, client)
	callOpts := &bind.CallOpts{}
	err := instance_token.Call(callOpts, &tokenDecimals, "decimals")
	if err != nil {
		return 0, fmt.Errorf("failed to retrieve value of variable: %v", err)
	}
	return int(tokenDecimals[0].(uint8)), nil
}

// TODO nick-0x test this as soon as you have the orderAggregator running. we need to have a order book to test this well
func GetBalanceMetaData_ZrxOrderBook(contractAddress common.Address, eventLog *Log) (ZRXOrderInfo, error) {
	// get the order hash from the event log
	orderHash := common.BytesToHash(eventLog.Data[0:32])
	log.Println("GetBalanceMetaData_ZrxOrderBook: orderHash", orderHash)

	// get the offChain data from orderDataStore
	order, ok := orderDataStore[orderHash.Hex()]
	if !ok {
		log.Println("GetBalanceMetaData_ZrxOrderBook: order not found in orderDataStore")
		return ZRXOrderInfo{}, fmt.Errorf("failed to get order from orderDataStore")
	}
	// do the OrderInfo call
	zrxOrder := ZRXOrder{
		Order:        order,
		OffChainData: order.OffChainData.(ZRXOffChainData),
	}
	return ZRXGetOrderInfo(zrxOrder)
}
