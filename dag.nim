import libsodium/sodium
import libsodium/sodium_sizes
import nimcrypto
import base58/cryptonote


type
  Block = object
    timestamp: int
    ancestors: seq[string]
    payload: string
    author: string
    btype: string
    pow: string


proc validateBlock(x: Block): bool = true
  ### Blocks hash must start with at least 4 zeros and the payload must be decryptable by the authors public key

proc validateBlockgraphIntegrety(bg: seq[Block]): bool = true
  ### A Block is invalid if:
  ### It references unknown blocks
  ### Its hash is insufficient
  ### The author cannot be verified
  ### It references Blocks from its future
  ### the type is invalid
  ### the payload content is invalid e.g. spending money already spent
