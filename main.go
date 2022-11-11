package main

/*
#cgo CFLAGS: -I./pkg/rsa
#cgo LDFLAGS: -L${SRCDIR}/pkg/rsa -lrsa
#include "rsa.h"
#include <string.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func RsaGenKeys(pub *C.struct_public_key_class, priv *C.struct_private_key_class, fpath string) {
	cfpath := C.CString(fpath)
	C.rsa_gen_keys(pub, priv, cfpath)
}

func RsaEncrypt(msg *C.char, msgSize C.ulong, pub *C.struct_public_key_class) *C.longlong {
	tmp := C.rsa_encrypt(msg, msgSize, pub)
	return (*C.longlong)(unsafe.Pointer(tmp))
}

func RsaDecrypt(msg *C.longlong, msgSize C.ulong, priv *C.struct_private_key_class) string {
	tmp := C.rsa_decrypt(msg, msgSize, priv)
	return C.GoString(tmp)
}

func main() {
	var pub C.struct_public_key_class
	var priv C.struct_private_key_class
	RsaGenKeys(&pub, &priv, "./pkg/rsa/primes.txt")
	fmt.Printf("Private Key: \n Modulus: %v\n Exponent: %v\n", priv.modulus, priv.exponent)
	fmt.Printf("Public Key: \n Modulus: %v\n Exponent: %v\n", pub.modulus, pub.exponent)

	str := "Guaderxx/cgodemo"
	original := C.CString(str)
	fmt.Printf("Original: %s\n", C.GoString(original))

	encrypted := RsaEncrypt(original, C.strlen(original), &pub)
	fmt.Printf("encrypted: %v\n", *encrypted)

	decrypted := RsaDecrypt(encrypted, 8*C.strlen(original), &priv)
	fmt.Printf("decrypted: %v\n", decrypted)

}
