# psql-mass-rce

Python3 script, which executes RCE on PostgreSQL. Accepts IP, network or .gnmap file as an argument.

Stages:
1. Check if port is open
2. Bruteforce credentials (using built-in dictionary or user argument)
3. Determine PostgreSQL version and OS
4. Execute RCE

Dependencies (just in case): `pip install argparse psycopg2 ipaddress`
