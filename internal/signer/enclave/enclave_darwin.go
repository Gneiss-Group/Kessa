// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin && cgo

package enclave

/*
#cgo darwin LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

// kessa_se_generate creates a P-256 key inside the Secure Enclave with an
// access-control policy: always private-key-usage; biometry-current-set added
// when biometric != 0. When permanent != 0 the key is stored in the keychain
// under applicationTag=tag (which needs a keychain-access-group entitlement, i.e.
// a properly code-signed binary); when permanent == 0 the key is ephemeral, lives
// only for the SecKeyRef's lifetime, touches no keychain, and needs no
// entitlement. The returned SecKeyRef is owned by the caller (release with
// kessa_se_release). Returns NULL on failure and sets *outErr to the CFError code.
static void* kessa_se_generate(const void* tag, int tagLen, int biometric, int permanent, long* outErr) {
    *outErr = 0;
    SecAccessControlCreateFlags flags = kSecAccessControlPrivateKeyUsage;
    if (biometric) flags |= kSecAccessControlBiometryCurrentSet;

    CFErrorRef acErr = NULL;
    SecAccessControlRef ac = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &acErr);
    if (ac == NULL) {
        *outErr = acErr ? (long)CFErrorGetCode(acErr) : -1;
        if (acErr) CFRelease(acErr);
        return NULL;
    }

    CFMutableDictionaryRef privAttrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(privAttrs, kSecAttrAccessControl, ac);
    CFDataRef tagData = NULL;
    if (permanent) {
        CFDictionarySetValue(privAttrs, kSecAttrIsPermanent, kCFBooleanTrue);
        tagData = CFDataCreate(kCFAllocatorDefault, (const UInt8*)tag, tagLen);
        CFDictionarySetValue(privAttrs, kSecAttrApplicationTag, tagData);
    } else {
        CFDictionarySetValue(privAttrs, kSecAttrIsPermanent, kCFBooleanFalse);
    }

    int bits = 256;
    CFNumberRef bitsNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);
    const void* keys[] = { kSecAttrKeyType, kSecAttrKeySizeInBits, kSecAttrTokenID, kSecPrivateKeyAttrs };
    const void* vals[] = { kSecAttrKeyTypeECSECPrimeRandom, bitsNum, kSecAttrTokenIDSecureEnclave, privAttrs };
    CFDictionaryRef attrs = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 4,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFErrorRef err = NULL;
    SecKeyRef key = SecKeyCreateRandomKey(attrs, &err);
    if (key == NULL) {
        *outErr = err ? (long)CFErrorGetCode(err) : -998;
    }
    if (err) CFRelease(err);
    CFRelease(attrs); CFRelease(bitsNum); CFRelease(privAttrs); if (tagData) CFRelease(tagData); CFRelease(ac);
    return (void*)key;
}

// kessa_se_load fetches the private SecKeyRef stored under applicationTag=tag.
// Returns NULL and sets *outStatus to the OSStatus (errSecItemNotFound when
// absent). The returned ref is owned by the caller.
static void* kessa_se_load(const void* tag, int tagLen, int* outStatus) {
    CFDataRef tagData = CFDataCreate(kCFAllocatorDefault, (const UInt8*)tag, tagLen);
    const void* keys[] = { kSecClass, kSecAttrApplicationTag, kSecAttrKeyType, kSecAttrKeyClass, kSecReturnRef };
    const void* vals[] = { kSecClassKey, tagData, kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClassPrivate, kCFBooleanTrue };
    CFDictionaryRef q = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 5,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef ref = NULL;
    OSStatus st = SecItemCopyMatching(q, &ref);
    CFRelease(q); CFRelease(tagData);
    *outStatus = (int)st;
    if (st != errSecSuccess) return NULL;
    return (void*)ref;
}

// kessa_se_sign signs data with key using ECDSA over SHA-256(data), returning an
// ASN.1 DER signature in a malloc'd *outSig (caller frees). Returns 0 on success.
static int kessa_se_sign(void* key, const void* data, int dataLen,
                         unsigned char** outSig, int* outSigLen, long* outErr) {
    *outErr = 0;
    CFDataRef dataRef = CFDataCreate(kCFAllocatorDefault, (const UInt8*)data, dataLen);
    CFErrorRef err = NULL;
    CFDataRef sig = SecKeyCreateSignature((SecKeyRef)key,
        kSecKeyAlgorithmECDSASignatureMessageX962SHA256, dataRef, &err);
    int rc = 0;
    if (sig == NULL) {
        *outErr = err ? (long)CFErrorGetCode(err) : -998;
        rc = -1;
    } else {
        CFIndex n = CFDataGetLength(sig);
        unsigned char* buf = (unsigned char*)malloc(n);
        memcpy(buf, CFDataGetBytePtr(sig), n);
        *outSig = buf; *outSigLen = (int)n;
        CFRelease(sig);
    }
    if (err) CFRelease(err);
    CFRelease(dataRef);
    return rc;
}

// kessa_se_public returns the X9.63 uncompressed public point (0x04||X||Y) of
// key's public half in a malloc'd *outPub (caller frees). Returns 0 on success.
static int kessa_se_public(void* key, unsigned char** outPub, int* outPubLen, long* outErr) {
    *outErr = 0;
    SecKeyRef pub = SecKeyCopyPublicKey((SecKeyRef)key);
    if (pub == NULL) { *outErr = -997; return -1; }
    CFErrorRef err = NULL;
    CFDataRef data = SecKeyCopyExternalRepresentation(pub, &err);
    int rc = 0;
    if (data == NULL) {
        *outErr = err ? (long)CFErrorGetCode(err) : -996;
        rc = -1;
    } else {
        CFIndex n = CFDataGetLength(data);
        unsigned char* buf = (unsigned char*)malloc(n);
        memcpy(buf, CFDataGetBytePtr(data), n);
        *outPub = buf; *outPubLen = (int)n;
        CFRelease(data);
    }
    if (err) CFRelease(err);
    CFRelease(pub);
    return rc;
}

// kessa_se_delete removes the key stored under applicationTag=tag. Returns the
// OSStatus (errSecSuccess or errSecItemNotFound if already gone).
static int kessa_se_delete(const void* tag, int tagLen) {
    CFDataRef tagData = CFDataCreate(kCFAllocatorDefault, (const UInt8*)tag, tagLen);
    const void* keys[] = { kSecClass, kSecAttrApplicationTag, kSecAttrKeyType };
    const void* vals[] = { kSecClassKey, tagData, kSecAttrKeyTypeECSECPrimeRandom };
    CFDictionaryRef q = CFDictionaryCreate(kCFAllocatorDefault, keys, vals, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    OSStatus st = SecItemDelete(q);
    CFRelease(q); CFRelease(tagData);
    return (int)st;
}

static void kessa_se_release(void* key) { if (key) CFRelease((CFTypeRef)key); }
*/
import "C"

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"unsafe"

	"github.com/Gneiss-Group/Kessa/pkg/types"
)

const (
	errSecItemNotFound       = -25300
	errSecMissingEntitlement = -34018
)

// Available reports that a Secure Enclave backend is compiled in. It does not
// probe the hardware; a machine without an Enclave will surface that as an error
// from Generate/Load instead.
func Available() bool { return true }

// Signer is a Secure Enclave-backed signer.Signer. The private key lives in the
// Enclave and is referenced only by an opaque SecKeyRef; Sign proxies to the
// Enclave, which performs SHA-256 + ECDSA-P256 and returns an ASN.1 DER
// signature. Close releases the ref. Signer is safe for concurrent Sign calls.
type Signer struct {
	did types.DID
	pub *ecdsa.PublicKey

	mu  sync.Mutex
	key unsafe.Pointer // SecKeyRef; nil after Close
}

// Generate creates a new non-extractable P-256 key in the Secure Enclave, stored
// PERMANENTLY in the keychain under tag with the given use policy, and returns a
// Signer over it. did is carried for DID() and is not interpreted here (the caller
// owns the DID<->tag mapping). A key already existing under tag is not overwritten
// by this call; delete it first or Load it.
//
// Persisting a Secure Enclave key requires a keychain-access-group entitlement,
// i.e. a properly code-signed binary; an unsigned/ad-hoc binary gets
// errSecMissingEntitlement here. See GenerateEphemeral for the entitlement-free
// path and docs/enclave-runbook.md for the signing setup.
func Generate(did types.DID, tag []byte, policy Policy) (*Signer, error) {
	if len(tag) == 0 {
		return nil, errors.New("enclave: empty tag")
	}
	return generate(did, tag, policy, true)
}

// GenerateEphemeral creates a non-extractable P-256 key in the Secure Enclave
// that is NOT stored in the keychain: it exists only until the Signer is closed
// or the process exits, and cannot be reloaded. Because it never touches the
// keychain it needs no entitlement, so it runs from an unsigned binary. It is the
// right tool for a short-lived signing need and for exercising the Enclave signing
// path in tests without a code-signing identity; it is NOT a durable device
// identity (use Generate for that).
func GenerateEphemeral(did types.DID, policy Policy) (*Signer, error) {
	return generate(did, nil, policy, false)
}

func generate(did types.DID, tag []byte, policy Policy, permanent bool) (*Signer, error) {
	bio := C.int(0)
	if policy == Biometric {
		bio = 1
	}
	perm := C.int(0)
	if permanent {
		perm = 1
	}
	var tagPtr unsafe.Pointer
	var tagLen C.int
	if len(tag) > 0 {
		tagPtr = unsafe.Pointer(&tag[0])
		tagLen = C.int(len(tag))
	} else {
		var z [1]byte
		tagPtr = unsafe.Pointer(&z[0])
	}
	var cerr C.long
	key := C.kessa_se_generate(tagPtr, tagLen, bio, perm, &cerr)
	if key == nil {
		if int64(cerr) == errSecMissingEntitlement {
			return nil, fmt.Errorf("enclave: generate key: %s: %w", oserr(int64(cerr)), ErrMissingEntitlement)
		}
		return nil, fmt.Errorf("enclave: generate key: %s", oserr(int64(cerr)))
	}
	return newSigner(did, key)
}

// Load returns a Signer over the key previously stored under tag, or ErrNotFound
// if none exists (so a caller can generate one). The Enclave enforces the key's
// original access-control policy on use regardless of how it is loaded.
func Load(did types.DID, tag []byte) (*Signer, error) {
	if len(tag) == 0 {
		return nil, errors.New("enclave: empty tag")
	}
	var st C.int
	key := C.kessa_se_load(unsafe.Pointer(&tag[0]), C.int(len(tag)), &st)
	if key == nil {
		if int(st) == errSecItemNotFound {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("enclave: load key: %s", oserr(int64(st)))
	}
	return newSigner(did, key)
}

// Delete removes the key stored under tag. It is not required for revocation
// (that is enforced server-side via the status list); it is local hygiene, e.g.
// re-enrollment on the same device. Deleting an absent key is not an error.
func Delete(tag []byte) error {
	if len(tag) == 0 {
		return errors.New("enclave: empty tag")
	}
	st := int(C.kessa_se_delete(unsafe.Pointer(&tag[0]), C.int(len(tag))))
	if st != 0 && st != errSecItemNotFound {
		return fmt.Errorf("enclave: delete key: %s", oserr(int64(st)))
	}
	return nil
}

// newSigner wraps a freshly obtained SecKeyRef: it eagerly reads and validates
// the public key (so callers never hold a Signer whose key is malformed) and
// arms a finalizer as a backstop for a missing Close.
func newSigner(did types.DID, key unsafe.Pointer) (*Signer, error) {
	pub, err := publicKey(key)
	if err != nil {
		C.kessa_se_release(key)
		return nil, err
	}
	s := &Signer{did: did, pub: pub, key: key}
	runtime.SetFinalizer(s, func(s *Signer) { _ = s.Close() })
	return s, nil
}

// Sign returns an ASN.1 DER ECDSA signature over SHA-256(data), computed by the
// Enclave. The output verifies under signer.Verify's P-256 branch unchanged.
func (s *Signer) Sign(data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil {
		return nil, errors.New("enclave: signer is closed")
	}
	// A zero-length message still needs a valid pointer for cgo; use a 1-byte
	// backing array and pass length 0.
	var ptr unsafe.Pointer
	if len(data) > 0 {
		ptr = unsafe.Pointer(&data[0])
	} else {
		var z [1]byte
		ptr = unsafe.Pointer(&z[0])
	}
	var outSig *C.uchar
	var outLen C.int
	var cerr C.long
	rc := C.kessa_se_sign(s.key, ptr, C.int(len(data)), &outSig, &outLen, &cerr)
	if rc != 0 {
		return nil, fmt.Errorf("enclave: sign: %s", oserr(int64(cerr)))
	}
	defer C.free(unsafe.Pointer(outSig))
	return C.GoBytes(unsafe.Pointer(outSig), outLen), nil
}

// Public returns the Enclave key's public half as a *ecdsa.PublicKey, ready for
// did.PublicKeyToJWK.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// DID returns the identifier this signer speaks for.
func (s *Signer) DID() types.DID { return s.did }

// Close releases the SecKeyRef. It is idempotent and safe to call more than once.
// It does NOT delete the key from the keychain (use Delete for that); it only
// drops this process's handle.
func (s *Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		C.kessa_se_release(s.key)
		s.key = nil
		runtime.SetFinalizer(s, nil)
	}
	return nil
}

// publicKey reads the X9.63 uncompressed point from a SecKeyRef and parses it
// into a validated *ecdsa.PublicKey. Validation goes through crypto/ecdh
// (on-curve, non-identity), matching did.JWK.PublicKey.
func publicKey(key unsafe.Pointer) (*ecdsa.PublicKey, error) {
	var outPub *C.uchar
	var outLen C.int
	var cerr C.long
	rc := C.kessa_se_public(key, &outPub, &outLen, &cerr)
	if rc != 0 {
		return nil, fmt.Errorf("enclave: read public key: %s", oserr(int64(cerr)))
	}
	defer C.free(unsafe.Pointer(outPub))
	x963 := C.GoBytes(unsafe.Pointer(outPub), outLen)

	if _, err := ecdh.P256().NewPublicKey(x963); err != nil {
		return nil, fmt.Errorf("enclave: enclave returned an invalid P-256 public key: %w", err)
	}
	if len(x963) != 65 || x963[0] != 0x04 {
		return nil, fmt.Errorf("enclave: unexpected public key encoding (%d bytes)", len(x963))
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x963[1:33]),
		Y:     new(big.Int).SetBytes(x963[33:65]),
	}, nil
}

// oserr renders a Security-framework OSStatus / CFError code, naming the ones a
// caller is likely to branch on.
func oserr(code int64) string {
	switch code {
	case -34018:
		return "errSecMissingEntitlement (-34018): key use needs a code-signed binary with a keychain-access-group entitlement"
	case errSecItemNotFound:
		return "errSecItemNotFound (-25300)"
	case -25293:
		return "errSecAuthFailed (-25293): access-control gate not satisfied"
	case -128:
		return "user canceled the authentication (-128)"
	case -25291:
		return "errSecNotAvailable (-25291): no keychain / secure element available"
	default:
		return fmt.Sprintf("Security framework error %d", code)
	}
}
