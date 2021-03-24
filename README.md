# nimcrypt
Nimcrypt is a .NET PE Crypter written in Nim, based entirely on the work of [@byt3bl33d3r](https://github.com/byt3bl33d3r)'s OffensiveNim project: https://github.com/byt3bl33d3r/OffensiveNim

This tool was inspired by [@S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t)'s blog post a few months ago, as it's essentially just a full PoC of what he presented: https://s3cur3th1ssh1t.github.io/Playing-with-OffensiveNim/

```
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

Usage:
  nimcrypt --file file_to_encrypt [--key <key> --output <output>]
  nimcrypt (-h | --help)
  nimcrypt --version
```

To compile and use nimcrypt, Nim and mingw-w64 must be installed. Nimble can then be used to install the rest of the dependencies:

```
nimble install nimcrypto
nimble install docopt
nimble install winim
```

Once all dependencies have been met, nimcrypt can be compiled with:
```
nim c -d=debug --cc:gcc --embedsrc=on --hints=on --app=console --cpu=amd64 --out=nimcrypt nimcrypt.nim
```


![alt text](https://i.imgur.com/TU6yGWj.gif)

This tool is not FUD, and may even be detected by defender now. Which is one of the reasons for it's public release ;)

I encourage you to read the source and modify it to bypass any signatures that are currently being detected. The main goal of posting this project was not to give the world a FUD crypter, but rather one that offensive security professionals can learn from and modify themselves for something more pratical.

Further References and Greetz:
* Xencrypt: https://github.com/the-xentropy/xencrypt (Taught me how crypters & AV work)
* PEzor: https://github.com/phra/PEzor (Cool tool, gave me inspiration to drop this)
* GENNA: https://twitter.com/CyberGuider (CyberGuider General & Commander-in-Cheif)
* Me: https://twitter.com/icyguider (Don't follow this guy he's boring and doesn't post)
