import libsodium/sodium
import libsodium/sodium_sizes
import nimcrypto
import base58/cryptonote
import random
import math
import strutils

randomize()


type
  Block = object
    timestamp: int
    ancestors: seq[string]
    ancestors_local: seq[int] #indices of the ancestors in the local block-sequence
    payload: string
    author: string
    btype: string
    pow: string #generated locally

func hashString(x: string): string = $keccak_256.digest(x)
func encode(x: string): string = cryptonote.encode(x)
func decode(x: string): string = cryptonote.decode(x)
func hashBlock(x: Block): string =
  var tempString = ""
  tempString &= $x.timestamp
  for a in x.ancestors:
    tempString &= a
  tempString &= x.payload
  tempString &= x.author
  tempString &= x.btype
  result = tempString.hashString()

func signMessage(sk, message: string): string =
  crypto_sign_detached(sk, message) #returns signature

func verifyMessage(pk, message, signature: string): bool =
  try:
    crypto_sign_verify_detached(pk,message,signature)
    result = true
  except:
    result = false


func validateBlock(x: Block): bool = true
  ### Blocks hash must start with at least 4 zeros and the payload must be decryptable by the authors public key

func validateBlockgraphIntegrety(bg: seq[Block]): bool = true
  ### A Block is invalid if:
  ### It references unknown blocks
  ### Its hash is insufficient
  ### The author cannot be verified
  ### It references Blocks from its future
  ### the type is invalid
  ### the payload content is invalid e.g. spending money already spent

var b = Block(timestamp: 1234, ancestors: @["a","b"], payload: "test", author:"bob", btype:"normal")
echo hashBlock(b)
b.timestamp = 345
echo hashBlock(b)
echo hashString("hello")
echo hashString("hello").encode()
echo encode("hello")
echo decode(encode("hello"))

echo "----"
let message = "Testing"
let (pk, sk) = crypto_sign_keypair()
let signature = signMessage(sk, message)
let valid = verifyMessage(pk,message,signature)
let (pk2, sk2) = crypto_sign_keypair()
let signature2 = signMessage(sk2, message)
let invalid = verifyMessage(pk, message, signature2)

echo encode(pk) & ":" & encode(pk2)
echo encode(sk) & ":" & encode(sk2)
echo encode(signature) & ":" & encode(signature2)
echo $valid
echo $invalid