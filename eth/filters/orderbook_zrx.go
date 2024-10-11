package filters

import (
	"log"
	"math/big"
	"fmt"
	"encoding/json"
	"time"
	"strconv"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
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
	OnChainData   ZRXOnChainData
}

// Raw structs are used to unmarshal data from the stream and convert it to the required format for contract calls.
type ZRXOffChainDataRaw struct {
	Order    ZRXOrderDetailsRaw `json:"order"`
	MetaData ZRXMetaData        `json:"metaData"`
}

type ZRXOrderDetailsRaw struct {
    Signature           ZRXSignature `json:"signature"`
    Sender              string       `json:"sender"`
    Maker               string       `json:"maker"`
    Taker               string       `json:"taker"`
    TakerTokenFeeAmount string       `json:"takerTokenFeeAmount"`
    MakerAmount         string       `json:"makerAmount"`
    TakerAmount         string       `json:"takerAmount"`
    MakerToken          string       `json:"makerToken"`
    TakerToken          string       `json:"takerToken"`
    Salt                string       `json:"salt"`
    VerifyingContract   string       `json:"verifyingContract"`
    FeeRecipient        string       `json:"feeRecipient"`
    Expiry              string       `json:"expiry"`
    ChainID             int          `json:"chainId"`
    Pool                string       `json:"pool"`
}

type ZRXOffChainData struct {
    Order    ZRXOrderDetails `json:"order"`
    MetaData ZRXMetaData     `json:"metaData"`
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
    MakerBalance_weiUnits    *big.Int     `json:"makerBalance_weiUnits"`
    MakerAllowance_weiUnits  *big.Int     `json:"makerAllowance_weiUnits"`
    OrderInfo                ZRXOrderInfo `json:"orderInfo"`
}

type ZRXOrderInfo struct {
    // OrderHash               [32]byte `json:"orderHash"`
    Status                  int      `json:"status"`
    TakerTokenFilledAmount  *big.Int `json:"takerTokenFilledAmount"`
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

    return ZRXOffChainData{
        Order: ZRXOrderDetails{
            Signature:           rawData.Order.Signature,
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
            ChainID:             rawData.Order.ChainID,
            Pool:                pool,
        },
        MetaData: rawData.MetaData,
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
        order.OffChainData = offChainData
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
		order.OffChainData.Order.Maker, order.OffChainData.Order.MakerToken)
    if err != nil {
        return onChainData, fmt.Errorf("failed to get maker balance: %v", err)
    }
    onChainData.MakerBalance_weiUnits = makerBalance_weiUnits

    // Retrieve the MakerAllowance_weiUnits (maker's allowance)
    // Assuming you have a function to get the allowance
    makerAllowance_weiUnits, err := GetERC20TokenAllowance(
		order.OffChainData.Order.MakerToken, order.OffChainData.Order.Maker, 
		order.OffChainData.Order.VerifyingContract)
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
        MakerToken              common.Address
        TakerToken              common.Address
        MakerAmount             *big.Int
        TakerAmount             *big.Int
        TakerTokenFeeAmount     *big.Int
        Maker                   common.Address
        Taker                   common.Address
        Sender                  common.Address
        FeeRecipient            common.Address
        Pool                    [32]byte
        Expiry                  uint64
        Salt                    *big.Int
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


func ZRXCreateOrder() {
    // Create a ZRX order
    time.Sleep(100 * time.Millisecond)
    order := Order{
        OrderHash:     "0x233a3f201fbac2b6ad99213d5cff89c23af647f3dbbfa089aef0ce814ebfdfd7",
        OrderBookName: ORDERBOOKNAME_ZRX,
        OffChainData: ZRXOffChainDataRaw{
            Order: ZRXOrderDetailsRaw{
                Signature: ZRXSignature{
                    SignatureType: 2,
                    R:             "0x9368e54e0fcc7e0203104ad2ff4ac15654524deedbdc7dbffe5a4627f0c66774",
                    S:             "0x41a8cea5e62ceaa40c145232f57a49a18f8cd3d14f8819792a267378e794c9ba",
                    V:             28,
                },
                Sender:              "0x0000000000000000000000000000000000000000",
                Maker:               "0x1e317156c06a89d27de6ba5c51138eee6d2d3bb7",
                Taker:               "0x0000000000000000000000000000000000000000",
                TakerTokenFeeAmount: "550660775000000000000",
                MakerAmount:         "5000000000",
                TakerAmount:         "220264310000000000000000",
                MakerToken:          "0xdac17f958d2ee523a2206206994597c13d831ec7",
                TakerToken:          "0x3be7bf1a5f23bd8336787d0289b70602f1940875",
                Salt:                "1727370123",
                VerifyingContract:   "0xdef1c0ded9bec7f1a1670819833240f027b25eff",
                FeeRecipient:        "0x9b858be6e3047d88820f439b240deac2418a2551",
                Expiry:              "1727456522",
                ChainID:             1,
                Pool:                "0x0000000000000000000000000000000000000000000000000000000000000000",
            },
            MetaData: ZRXMetaData{
                OrderHash:                    "0x233a3f201fbac2b6ad99213d5cff89c23af647f3dbbfa089aef0ce814ebfdfd7",
                RemainingFillableTakerAmount: "220264310000000000000000",
                CreatedAt:                    "2024-09-26T17:02:22.265Z",
            },
        },
    }

    log.Println("ZRXCreateOrder: order created and going to write to stream")

    // TODO-nick oan later we want to remove this and use the shared Redis stream to get orders and store them
    //  we do this later because we want to use the actual orderAggregatorNinja to convert it from. this here is just for debugging
    orderDataStore[order.OrderHash] = order
    // Write the order to the shared Redis stream
    writeUpdateToStream(ConvertZRXOrderToMap(order))
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