package cryptutil

import "strings"

type DigestAlgorithm string

// RFC 5751 page 29
const (
	MD5         = DigestAlgorithm("md5")   // Deprecated
	SHA1        = DigestAlgorithm("sha-1") // Deprecated
	SHA256      = DigestAlgorithm("sha-256")
	SHA384      = DigestAlgorithm("sha-384")
	SHA512      = DigestAlgorithm("sha-512")
	SHA224      = DigestAlgorithm("sha-224")
	SHA3_256    = DigestAlgorithm("sha3-256")
	SHA3_384    = DigestAlgorithm("sha3-384")
	SHA3_512    = DigestAlgorithm("sha3-512")
	SHA3_224    = DigestAlgorithm("sha3-224")
	BLAKE2S_256 = DigestAlgorithm("blake2s-256")
	BLAKE2B_256 = DigestAlgorithm("blake2b-256")
	BLAKE2B_384 = DigestAlgorithm("blake2b-384")
	BLAKE2B_512 = DigestAlgorithm("blake2b-512")
)

func CanonicalDigestAlgorithm(algorithm string) DigestAlgorithm {
	algorithm = strings.ToLower(algorithm)
	switch algorithm {
	case "md5", "md-5", "rsa-md5":
		return MD5
	case "sha1", "sha-1", "rsa-sha1":
		return SHA1
	case "sha256", "sha-256":
		return SHA256
	case "sha384", "sha-384":
		return SHA384
	case "sha512", "sha-512":
		return SHA512
	case "sha224", "sha-224":
		return SHA224
	case "sha3-256":
		return SHA3_256
	case "sha3-384":
		return SHA3_384
	case "sha3-512":
		return SHA3_512
	case "sha3-224":
		return SHA3_224
	case "blake2s-256":
		return BLAKE2S_256
	case "blake2b-256":
		return BLAKE2B_256
	case "blake2b-384":
		return BLAKE2B_384
	case "blake2b-512":
		return BLAKE2B_512
	default:
		return DigestAlgorithm(algorithm)
	}
}
