# cryptopals
Solutions to the original Matasano Cryptopals challenges in Python 3.6.

## Overview
Here are my solutions to the original 6 sets of 48 Matasano [Cryptopals](https://cryptopals.com/)
programming challenges, implemented in Python 3.6. I intend to complete Sets 7 and 8 at some point.

## Demos
| ![Demo: Solution 46](https://raw.githubusercontent.com/kangtastic/cryptopals/gh-pages/demo.gif "Solution 46") | 
|:--:| 
| *Solution 46* |

| ![Demo: Solution 48](https://raw.githubusercontent.com/kangtastic/cryptopals/gh-pages/demo2.gif "Solution 48") | 
|:--:| 
| *Solution 48* |

## Requirements
- Python 3.6+
- [Pycryptodome](https://www.pycryptodome.org/en/latest/) (optional, but greatly speeds up AES if it's present)

Why 3.6? [f-strings](https://www.python.org/dev/peps/pep-0498/), mostly. Also,
[ThreadingHTTPServer](https://docs.python.org/3/library/http.server.html#http.server.ThreadingHTTPServer)
(trivially backported from 3.7) is used once. Maybe some other 3.6+ features are too, I dunno.

## Usage
Each solution is a script that can be run on its own. Any required servers will be started by the
script.

Running them for yourself should be as easy as running them for yourself:
```
    $ ./cxx_script_name.py
    
    or
    
    $ python3.6 ./cXX_script_name.py
```

## Disclaimers
Long-term I'd like to work on these, but at the moment:
- Clean, performant, secure code this is not. Try "hacky". "Babby's first" isn't too far off.
- Handling `SIGINT` or <kbd>Ctrl</kbd>+<kbd>C</kbd> while `multiprocessing` is tested on Linux only.
- Documentation is hit-or-miss.
- A couple of attacks don't work all the time on all platforms.

## Legal
All of my original work in this repository is released under the
[WTFPL](http://www.wtfpl.net/txt/copying/) Version 2.
