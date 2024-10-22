// {'maker': '0xf7f9912512a5447295c872f35e157f4dd3f60af7', 'makerToken': '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
// 'makerAmount': 310000000000000000, 'takerTokenRecipient': '0xf7f9912512a5447295c872f35e157f4dd3f60af7',
// 'takerToken': '0x6b175474e89094c44da98b954eedeac495271d0f', 'takerAmountMin': 500000000000000000000,
// 'takerAmountDecayRate': 0, 'data': 182731631036575856403770922421532039922998,
// 'signature': '0x7ec8608224dd78be12fc43c91ea29c24b4e298815ee39720b6733c314b6671561193ddbcb43f34f0bf19b47f3f776249eaf28d36617a79924b46eb8c76ff6f031b',
// 'orderHash': '0xd8d443522637eb23b5355b881aa8062237877700bf7cfed9b9ee1034523dde8d',
//
//	'dataDecoded': {
//			'begin': 1729185078, 'expiry': 1729385078, 'partiallyFillable': True, 'authorization': False,
//			'usePermit2': False, 'nonce': 67}, 'makerAmountFilled': 0, 'status': 'fillable', 'statusTimeline': [{'status': 'fillable', 'timestamp': '2024-10-17T17:11:18Z', 'slotNumber': 10196754, 'blockNumber': 20986691}], 'fills': []}
package filters

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"log"
	"math/big"
)

var (
	ORDERBOOKNAME_TEMPO = "tempo"
)

// list of Tempo contract addresses
var TEMPO_CONTRACT = common.HexToAddress("0x93be362993d5B3954dbFdA49A1Ad1844c8083A30")

type TempoOrder struct {
	Order
	OffChainData TempoOffChainData_SignedOrder
	OnChainData  TempoOnChainData
}

type TempoOrderRaw struct {
	Order
	OffChainData TempoOffChainDataRaw
	OnChainData  TempoOnChainData
}

type TempoOffChainDataRaw struct {
	Maker                string `json:"maker"`
	MakerToken           string `json:"makerToken"`
	MakerAmount          string `json:"makerAmount"`
	TakerTokenRecipient  string `json:"takerTokenRecipient"`
	TakerToken           string `json:"takerToken"`
	TakerAmountMin       string `json:"takerAmountMin"`
	TakerAmountDecayRate string `json:"takerAmountDecayRate"`
	Data                 string `json:"data"`
	Signature            string `json:"signature"`
	OrderHash            string `json:"orderHash"`
}

type TempoOffChainData_SignedOrder struct {
	Order     TempoOffChainDataOrder `json:"order"`
	Signature []byte                 `json:"signature"`
	// not sure if we need this because it is already a field of Order
	// OrderHash              common.Hash            `json:"orderHash"`
}

// TODO nick-0x why is a dataDecoded field getting set? we are not defining it here
type TempoOffChainDataOrder struct {
	Maker                common.Address `json:"maker"`
	MakerToken           common.Address `json:"makerToken"`
	MakerAmount          *big.Int       `json:"makerAmount"`
	TakerTokenRecipient  common.Address `json:"takerTokenRecipient"`
	TakerToken           common.Address `json:"takerToken"`
	TakerAmountMin       *big.Int       `json:"takerAmountMin"`
	TakerAmountDecayRate *big.Int       `json:"takerAmountDecayRate"`
	Data                 *big.Int       `json:"data"`
	// VerifyingContract    common.Address `json:"verifyingContract,omitempty"`
	// ChainID              int            `json:"chainId,omitempty"`
}

type TempoOnChainData struct {
	MakerBalance_weiUnits   *big.Int       `json:"makerBalance_weiUnits"`
	MakerAllowance_weiUnits *big.Int       `json:"makerAllowance_weiUnits"`
	OrderInfo               TempoOrderInfo `json:"orderInfo"`
}

type TempoOrderInfo struct {
	// OrderHash           common.Hash `json:"orderHash"`
	OrderStatus         int      `json:"orderStatus"`
	MakerAmountFilled   *big.Int `json:"makerAmountFilled"`
	MakerAmountFillable *big.Int `json:"makerAmountFillable"`
}

type TempoData struct {
	Begin             int
	Expiry            int
	PartiallyFillable int
	Authorization     int
	UsePermit2        int
	Nonce             int
}

// this should only be for debugging purposes - not even sure it works
func TempoDecodeOrderDataInt(data *big.Int) (TempoData, error) {
	var tempoData TempoData
	dataInt := data.Int64()
	tempoData.Begin = int(dataInt & 0xffffffff)
	tempoData.Expiry = int((dataInt >> 32) & 0xffffffff)
	tempoData.PartiallyFillable = int((dataInt >> 64) & 0x1)
	tempoData.Authorization = int((dataInt >> 65) & 0x1)
	tempoData.UsePermit2 = int((dataInt >> 66) & 0x1)
	tempoData.Nonce = int((dataInt >> 67) & 0xffffffff)
	return tempoData, nil
}

// MarshalJSON implements the json.Marshaler interface for TempoOffChainData_SignedOrder
func (o TempoOffChainData_SignedOrder) MarshalJSON() ([]byte, error) {
	type Alias TempoOffChainData_SignedOrder
	return json.Marshal(&struct {
		Signature string `json:"signature"`
		*Alias
	}{
		Signature: fmt.Sprintf("0x%x", o.Signature),
		Alias:     (*Alias)(&o),
	})
}

func TempoConvertOrderToTempoOrder(order Order) (TempoOrder, error) {
	log.Println("TempoConvertOrderToTempoOrder: order: ", order)
	tempoOrderRaw, err := TempoConvertOrderToTempoOrderRaw(order)
	if err != nil {
		return TempoOrder{}, fmt.Errorf(
			"TempoConvertOrderToTempoOrder: failed to convert order to TempoOrderRaw: %v", err)
	}
	log.Println("TempoConvertOrderToTempoOrder: tempoOrderRaw: ", tempoOrderRaw)
	tempoOrder, err := TempoConvertTempoOrderRawToTempoOrder(tempoOrderRaw)
	if err != nil {
		return TempoOrder{}, fmt.Errorf(
			"TempoConvertOrderToTempoOrder: failed to convert TempoOrderRaw to TempoOrder: %v", err)
	}
	log.Println("TempoConvertOrderToTempoOrder: tempoOrder: ", tempoOrder)
	return tempoOrder, nil
}

func TempoConvertOrderToTempoOrderRaw(order Order) (TempoOrderRaw, error) {
	var tempoOrderRaw TempoOrderRaw

	// convert the order to TempoOrderRaw
	tempoOrderRaw.Order = order

	log.Println("TempoConvertOrderToTempoOrderRaw: order: ", order)
	log.Println("TempoConvertOrderToTempoOrderRaw: offChainData: ", order.OffChainData)
	// convert the offChainData to TempoOffChainDataRaw
	offChainData, ok := order.OffChainData.(TempoOffChainDataRaw)
	if !ok {
		// Attempt to manually unmarshal the offChainData
		data, err := json.Marshal(order.OffChainData)
		if err != nil {
			return tempoOrderRaw, fmt.Errorf("failed to marshal offChainData: %v", err)
		}
		var tempoOffChainDataRaw TempoOffChainDataRaw
		err = json.Unmarshal(data, &tempoOffChainDataRaw)
		if err != nil {
			return tempoOrderRaw, fmt.Errorf("failed to unmarshal offChainData: %v", err)
		}
		offChainData = tempoOffChainDataRaw
	}
	tempoOrderRaw.OffChainData = offChainData

	log.Printf("TempoConvertOrderToTempoOrderRaw: Successfully converted offChainData: %+v", offChainData)
	return tempoOrderRaw, nil
}

func TempoConvertTempoOrderRawToTempoOrder(tempoOrderRaw TempoOrderRaw) (TempoOrder, error) {
	var tempoOrder TempoOrder

	// convert the order to TempoOrder
	tempoOrder.Order = tempoOrderRaw.Order

	// convert the offChainData to TempoOffChainData_SignedOrder
	offChainData, err := CreateTempoOffChainData(tempoOrderRaw.OffChainData)
	if err != nil {
		return tempoOrder, fmt.Errorf("failed to convert offChainData to TempoOffChainData_SignedOrder: %v", err)
	}
	tempoOrder.OffChainData = offChainData

	return tempoOrder, nil
}

func CreateTempoOffChainData(tempoOffChainDataRaw TempoOffChainDataRaw) (TempoOffChainData_SignedOrder, error) {
	var tempoOffChainData TempoOffChainData_SignedOrder

	// Helper function to convert string to *big.Int
	toBigInt := func(value string) *big.Int {
		bigIntValue, ok := new(big.Int).SetString(value, 10)
		if !ok {
			log.Fatalf("invalid value: %s", value)
		}
		return bigIntValue
	}

	// Convert the order to TempoOffChainDataOrder
	offChainDataOrder := TempoOffChainDataOrder{
		Maker:                common.HexToAddress(tempoOffChainDataRaw.Maker),
		MakerToken:           common.HexToAddress(tempoOffChainDataRaw.MakerToken),
		MakerAmount:          toBigInt(tempoOffChainDataRaw.MakerAmount),
		TakerTokenRecipient:  common.HexToAddress(tempoOffChainDataRaw.TakerTokenRecipient),
		TakerToken:           common.HexToAddress(tempoOffChainDataRaw.TakerToken),
		TakerAmountMin:       toBigInt(tempoOffChainDataRaw.TakerAmountMin),
		TakerAmountDecayRate: toBigInt(tempoOffChainDataRaw.TakerAmountDecayRate),
		Data:                 toBigInt(tempoOffChainDataRaw.Data),
	}

	// Convert the signature to []byte
	signature := common.FromHex(tempoOffChainDataRaw.Signature)

	tempoOffChainData.Order = offChainDataOrder
	tempoOffChainData.Signature = signature

	return tempoOffChainData, nil
}

func TempoGetOnChainData(tempoOrder TempoOrder) (OnChainData, error) {
	var onChainData OnChainData

	// at this point we do only have the offchain data. we need to fetch the onchain data from the blockchain

	// get the maker balance
	onChainData.MakerBalance_weiUnits, err = GetERC20TokenBalance(
		tempoOrder.OffChainData.Order.Maker, tempoOrder.OffChainData.Order.MakerToken)
	if err != nil {
		return onChainData, fmt.Errorf("failed to get maker balance: %v", err)
	}

	// check if it is a permit2 order
	decodedDataInt, err := TempoDecodeOrderDataInt(tempoOrder.OffChainData.Order.Data)
	if err != nil {
		return onChainData, fmt.Errorf("failed to decode order data: %v", err)
	}
	// if permit2 order
	if decodedDataInt.UsePermit2 == 1 {
		log.Println("permit2 order found")
		// get the maker allowance set in the permit2 contract
		// log an error to integrate this part
		log.Fatalln("permit2 allowance check not implemented yet")
	} else {
		log.Println("no permit2 order found")
		// get the maker allowance set in the maker token contract
		onChainData.MakerAllowance_weiUnits, err = GetERC20TokenAllowance(
			tempoOrder.OffChainData.Order.MakerToken, tempoOrder.OffChainData.Order.Maker, TEMPO_CONTRACT)
		if err != nil {
			return onChainData, fmt.Errorf("failed to get maker allowance: %v", err)
		}
	}

	// get the order info
	onChainData.OrderInfo, err = TempoGetOrderInfo(tempoOrder)
	if err != nil {
		return onChainData, fmt.Errorf("failed to get order info: %v", err)
	}

	return onChainData, nil

}

func TempoGetOrderInfo(tempoOrder TempoOrder) (TempoOrderInfo, error) {
	log.Println("TempoGetOrderInfo: tempoOrder: ", tempoOrder)
	log.Println("TempoGetOrderInfo: orderHash: ", tempoOrder.Order.OrderHash)

	var orderInfoResponse []interface{}

	instance_tempoContract := bind.NewBoundContract(TEMPO_CONTRACT, parsedABI_Tempo, client, client, client)

	log.Println("TempoGetOrderInfo: contractAddress", TEMPO_CONTRACT)

	// TODO nick-0x remove that again if the call works
	// {
	//     "inputs": [
	//         {
	//             "components": [
	//                 {
	//                     "components": [
	//                         {
	//                             "internalType": "address",
	//                             "name": "maker",
	//                             "type": "address"
	//                         },
	//                         {
	//                             "internalType": "address",
	//                             "name": "makerToken",
	//                             "type": "address"
	//                         },
	//                         {
	//                             "internalType": "uint256",
	//                             "name": "makerAmount",
	//                             "type": "uint256"
	//                         },
	//                         {
	//                             "internalType": "address",
	//                             "name": "takerTokenRecipient",
	//                             "type": "address"
	//                         },
	//                         {
	//                             "internalType": "address",
	//                             "name": "takerToken",
	//                             "type": "address"
	//                         },
	//                         {
	//                             "internalType": "uint256",
	//                             "name": "takerAmountMin",
	//                             "type": "uint256"
	//                         },
	//                         {
	//                             "internalType": "uint256",
	//                             "name": "takerAmountDecayRate",
	//                             "type": "uint256"
	//                         },
	//                         {
	//                             "internalType": "uint256",
	//                             "name": "data",
	//                             "type": "uint256"
	//                         }
	//                     ],
	//                     "internalType": "struct Order",
	//                     "name": "order",
	//                     "type": "tuple"
	//                 },
	//                 {
	//                     "internalType": "bytes",
	//                     "name": "signature",
	//                     "type": "bytes"
	//                 }
	//             ],
	//             "internalType": "struct SignedOrder",
	//             "name": "order",
	//             "type": "tuple"
	//         }
	//     ],
	//     "name": "getOrderStatus",
	//     "outputs": [
	//         {
	//             "components": [
	//                 {
	//                     "internalType": "bytes32",
	//                     "name": "orderHash",
	//                     "type": "bytes32"
	//                 },
	//                 {
	//                     "internalType": "enum OrderUtils.OrderStatus",
	//                     "name": "status",
	//                     "type": "uint8"
	//                 },
	//                 {
	//                     "internalType": "uint256",
	//                     "name": "makerAmountFilled",
	//                     "type": "uint256"
	//                 },
	//                 {
	//                     "internalType": "uint256",
	//                     "name": "makerAmountFillable",
	//                     "type": "uint256"
	//                 }
	//             ],
	//             "internalType": "struct OrderUtils.OrderInfo",
	//             "name": "orderInfo",
	//             "type": "tuple"
	//         }
	//     ],
	//     "stateMutability": "view",
	//     "type": "function"
	// }

	inputParameters := &struct {
		Order     TempoOffChainDataOrder `json:"order"`
		Signature []byte                 `json:"signature"`
	}{
		Order: TempoOffChainDataOrder{
			Maker:                tempoOrder.OffChainData.Order.Maker,
			MakerToken:           tempoOrder.OffChainData.Order.MakerToken,
			MakerAmount:          tempoOrder.OffChainData.Order.MakerAmount,
			TakerTokenRecipient:  tempoOrder.OffChainData.Order.TakerTokenRecipient,
			TakerToken:           tempoOrder.OffChainData.Order.TakerToken,
			TakerAmountMin:       tempoOrder.OffChainData.Order.TakerAmountMin,
			TakerAmountDecayRate: tempoOrder.OffChainData.Order.TakerAmountDecayRate,
			Data:                 tempoOrder.OffChainData.Order.Data,
		},
		Signature: tempoOrder.OffChainData.Signature,
	}

	// lets decode the data and print the values
	// Log the entire tempoOrder structure
	log.Println("TempoGetOrderInfo: tempoOrder: ", tempoOrder)
	// Log the OffChainData
	log.Println("TempoGetOrderInfo: tempoOrder.OffChainData: ", tempoOrder.OffChainData)
	// Log the Order
	log.Println("TempoGetOrderInfo: tempoOrder.OffChainData.Order: ", tempoOrder.OffChainData.Order)
	// Log the Data field
	log.Println("TempoGetOrderInfo: tempoOrder.OffChainData.Order.Data: ", tempoOrder.OffChainData.Order.Data)
	decodedData, err := TempoDecodeOrderDataInt(tempoOrder.OffChainData.Order.Data)
	if err != nil {
		log.Println("TempoGetOrderInfo: failed to decode order data: ", err)
		return TempoOrderInfo{}, err
	}
	log.Println("TempoGetOrderInfo: decodedData: ", decodedData)

	// Call the getOrderStatus function on the contract
	callOpts := &bind.CallOpts{}
	err = instance_tempoContract.Call(callOpts, &orderInfoResponse, "getOrderStatus", inputParameters)
	if err != nil {
		log.Println("TempoGetOrderInfo: failed to get order info: ", err)
		return TempoOrderInfo{}, err
	}
	log.Println("TempoGetOrderInfo: orderInfoResponse", orderInfoResponse)

	// Assert the response to the expected struct
	orderInfo := orderInfoResponse[0].(struct {
		OrderHash           [32]byte `json:"orderHash"`
		Status              uint8    `json:"status"`
		MakerAmountFilled   *big.Int `json:"makerAmountFilled"`
		MakerAmountFillable *big.Int `json:"makerAmountFillable"`
	})

	// make sure the OrderHash matches order.OrderHash
	log.Println("tempoOrder.Order.OrderHash", tempoOrder.Order.OrderHash)
	log.Println("orderInfo.OrderHash", common.BytesToHash(orderInfo.OrderHash[:]).Hex())
	if tempoOrder.Order.OrderHash != common.BytesToHash(orderInfo.OrderHash[:]).Hex() {
		log.Println("TempoGetOrderInfo: orderHash does not match. This can happen while testing," +
			"because the order was created in local env but we are querying the blockchain")
	}

	return TempoOrderInfo{
		OrderStatus:         int(orderInfo.Status),
		MakerAmountFilled:   orderInfo.MakerAmountFilled,
		MakerAmountFillable: orderInfo.MakerAmountFillable,
	}, nil
}

func GetBalanceMetaData_TempoOrderBook(contractAddress common.Address, eventLog *Log) (TempoOrderInfo, error) {
	orderHash := common.BytesToHash(eventLog.Data[0:32])
	log.Println("GetBalanceMetaData_TempoOrderBook: orderHash: ", orderHash)

	// get the offChain data from orderDataStore
	order, ok := orderDataStore[orderHash.Hex()]
	if !ok {
		log.Println("GetBalanceMetaData_ZrxOrderBook: order not found in orderDataStore")
		return TempoOrderInfo{}, fmt.Errorf("failed to get order from orderDataStore")
	}

	// Check if OffChainData is of the expected type
	offChainData, ok := order.OffChainData.(TempoOffChainData_SignedOrder)
	if !ok {
		log.Println("GetBalanceMetaData_TempoOrderBook: OffChainData is not of type TempoOffChainData_SignedOrder")
		return TempoOrderInfo{}, fmt.Errorf("OffChainData is not of type TempoOffChainData_SignedOrder")
	}

	// do the OrderInfo call
	tempoOrder := TempoOrder{
		Order:        order,
		OffChainData: offChainData,
	}
	return TempoGetOrderInfo(tempoOrder)
}
