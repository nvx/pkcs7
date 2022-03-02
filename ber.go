package pkcs7

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"sort"
)

type asn1Object interface {
	EncodeTo(writer *bytes.Buffer) error
}

type asn1Structured struct {
	tagBytes []byte
	content  []asn1Object
}

func concatStringTypes(tagType byte, content []asn1Object) ([]byte, error) {
	out := new(bytes.Buffer)

	for _, c := range content {
		var str []byte
		switch c := c.(type) {
		case asn1Primitive:
			if len(c.tagBytes) != 1 || c.tagBytes[0] != tagType {
				return nil, errors.New("ber2der: mixed string types in constructed string")
			}
			str = c.content
		case asn1Structured:
			if len(c.tagBytes) != 1 || c.tagBytes[0]&^0x20 != tagType {
				return nil, errors.New("ber2der: mixed string types in constructed string")
			}
			var err error
			str, err = concatStringTypes(tagType, c.content)
			if err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("ber2der: got unknown object type")
		}

		_, err := out.Write(str)
		if err != nil {
			return nil, err
		}
	}

	return out.Bytes(), nil
}

func (s asn1Structured) EncodeTo(out *bytes.Buffer) error {
	var needSort bool
	if len(s.tagBytes) == 1 {
		tag := s.tagBytes[0] &^ 0x20 // Clear structured bit
		switch tag {
		case asn1.TagSet:
			// DER requires SETs to be sorted by Tag
			needSort = true
		case asn1.TagBitString, asn1.TagOctetString, asn1.TagUTF8String, asn1.TagNumericString, asn1.TagPrintableString,
			asn1.TagT61String, asn1.TagIA5String, asn1.TagUTCTime, asn1.TagGeneralizedTime, asn1.TagGeneralString, asn1.TagBMPString:
			// DER requires strings to be encoded as primitive types
			content, err := concatStringTypes(tag, s.content)
			if err != nil {
				return err
			}
			prim := asn1Primitive{
				tagBytes: []byte{tag},
				content:  content,
			}
			return prim.EncodeTo(out)
		}
	}

	inner := new(bytes.Buffer)
	var sortBuf [][]byte

	for _, obj := range s.content {
		err := obj.EncodeTo(inner)
		if err != nil {
			return err
		}

		if needSort {
			sortBuf = append(sortBuf, inner.Bytes())
			inner = new(bytes.Buffer) // fresh buffer for next time
		}
	}

	if needSort {
		sort.Slice(sortBuf, func(i, j int) bool {
			return bytes.Compare(sortBuf[i], sortBuf[j]) == -1
		})

		for _, buf := range sortBuf {
			_, err := inner.Write(buf)
			if err != nil {
				return err
			}
		}
	}

	_, err := out.Write(s.tagBytes)
	if err != nil {
		return err
	}

	err = encodeLength(out, inner.Len())
	if err != nil {
		return err
	}

	_, err = out.Write(inner.Bytes())
	if err != nil {
		return err
	}

	return nil
}

type asn1Primitive struct {
	tagBytes []byte
	content  []byte
}

func (p asn1Primitive) EncodeTo(out *bytes.Buffer) error {
	_, err := out.Write(p.tagBytes)
	if err != nil {
		return err
	}

	err = encodeLength(out, len(p.content))
	if err != nil {
		return err
	}

	_, err = out.Write(p.content)
	if err != nil {
		return err
	}

	return nil
}

func ber2der(ber []byte) ([]byte, error) {
	if len(ber) == 0 {
		return nil, errors.New("ber2der: input ber is empty")
	}
	//fmt.Printf("--> ber2der: Transcoding %d bytes\n", len(ber))
	out := new(bytes.Buffer)

	obj, _, err := readObject(ber, 0)
	if err != nil {
		return nil, err
	}

	err = obj.EncodeTo(out)
	if err != nil {
		return nil, err
	}

	// if offset < len(ber) {
	//	return nil, fmt.Errorf("ber2der: Content longer than expected. Got %d, expected %d", offset, len(ber))
	//}

	return out.Bytes(), nil
}

// encodes lengths that are longer than 127 into string of bytes
func marshalLongLength(out *bytes.Buffer, i int) (err error) {
	n := lengthLength(i)

	for ; n > 0; n-- {
		err = out.WriteByte(byte(i >> uint((n-1)*8)))
		if err != nil {
			return
		}
	}

	return nil
}

// computes the byte length of an encoded length value
func lengthLength(i int) (numBytes int) {
	numBytes = 1
	for i > 255 {
		numBytes++
		i >>= 8
	}
	return
}

// encodes the length in DER format
// If the length fits in 7 bits, the value is encoded directly.
//
// Otherwise, the number of bytes to encode the length is first determined.
// This number is likely to be 4 or less for a 32bit length. This number is
// added to 0x80. The length is encoded in big endian encoding follow after
//
// Examples:
//  length | byte 1 | bytes n
//  0      | 0x00   | -
//  120    | 0x78   | -
//  200    | 0x81   | 0xC8
//  500    | 0x82   | 0x01 0xF4
//
func encodeLength(out *bytes.Buffer, length int) (err error) {
	if length >= 128 {
		l := lengthLength(length)
		err = out.WriteByte(0x80 | byte(l))
		if err != nil {
			return
		}
		err = marshalLongLength(out, length)
		if err != nil {
			return
		}
	} else {
		err = out.WriteByte(byte(length))
		if err != nil {
			return
		}
	}
	return
}

func readObject(ber []byte, offset int) (asn1Object, int, error) {
	berLen := len(ber)
	if offset >= berLen {
		return nil, 0, errors.New("ber2der: offset is after end of ber data")
	}
	tagStart := offset
	b := ber[offset]
	offset++
	if offset >= berLen {
		return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
	}
	tag := int(b & 0x1F) // last 5 bits
	if tag == 0x1F {
		tag = 0
		for {
			tag = tag*0x80 + int(ber[offset]&0x7F)
			offset++
			if offset > berLen {
				return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
			}
			if ber[offset-1]&0x80 != 0x80 {
				break
			}
		}
	}
	tagEnd := offset

	kind := b & 0x20
	if kind == 0 {
		debugprint("--> Primitive\n")
	} else {
		debugprint("--> Constructed\n")
	}
	// read length
	var length int
	l := ber[offset]
	offset++
	if offset > berLen {
		return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
	}
	indefinite := false
	if l > 0x80 {
		numberOfBytes := (int)(l & 0x7F)
		if numberOfBytes > 4 { // int is only guaranteed to be 32bit
			return nil, 0, errors.New("ber2der: BER tag length too long")
		}
		if numberOfBytes == 4 && (int)(ber[offset]) > 0x7F {
			return nil, 0, errors.New("ber2der: BER tag length is negative")
		}
		if (int)(ber[offset]) == 0x0 {
			return nil, 0, errors.New("ber2der: BER tag length has leading zero")
		}
		debugprint("--> (compute length) indicator byte: %x\n", l)
		debugprint("--> (compute length) length bytes: %X\n", ber[offset:offset+numberOfBytes])
		for i := 0; i < numberOfBytes; i++ {
			length = length*256 + (int)(ber[offset])
			offset++
			if offset > berLen {
				return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
			}
		}
	} else if l == 0x80 {
		indefinite = true
	} else {
		length = (int)(l)
	}
	if length < 0 {
		return nil, 0, errors.New("ber2der: invalid negative value found in BER tag length")
	}
	//fmt.Printf("--> length        : %d\n", length)
	contentEnd := offset + length
	if contentEnd > len(ber) {
		return nil, 0, errors.New("ber2der: BER tag length is more than available data")
	}
	debugprint("--> content start : %d\n", offset)
	debugprint("--> content end   : %d\n", contentEnd)
	debugprint("--> content len   : %d\n", length)
	debugprint("--> content       : %X\n", ber[offset:contentEnd])
	var obj asn1Object
	if indefinite && kind == 0 {
		return nil, 0, errors.New("ber2der: Indefinite form tag must have constructed encoding")
	}
	if kind == 0 {
		obj = asn1Primitive{
			tagBytes: ber[tagStart:tagEnd],
			content:  ber[offset:contentEnd],
		}
	} else {
		var subObjects []asn1Object
		for (offset < contentEnd) || indefinite {
			if indefinite {
				terminated, err := isIndefiniteTermination(ber, offset)
				if err != nil {
					return nil, 0, err
				}

				if terminated {
					break
				}
			}

			var subObj asn1Object
			var err error
			subObj, offset, err = readObject(ber, offset)
			if err != nil {
				return nil, 0, err
			}
			subObjects = append(subObjects, subObj)
		}
		obj = asn1Structured{
			tagBytes: ber[tagStart:tagEnd],
			content:  subObjects,
		}
	}

	// Apply indefinite form length with 0x0000 terminator.
	if indefinite {
		contentEnd = offset + 2
	}

	return obj, contentEnd, nil
}

func isIndefiniteTermination(ber []byte, offset int) (bool, error) {
	if len(ber)-offset < 2 {
		return false, errors.New("ber2der: Invalid BER format")
	}

	return bytes.Index(ber[offset:], []byte{0x0, 0x0}) == 0, nil
}

func debugprint(format string, a ...interface{}) {
	//fmt.Printf(format, a...)
}
