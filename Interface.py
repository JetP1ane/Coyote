# coding=utf-8

from cmd2 import Cmd
from binascii import hexlify, unhexlify
from Coyote import *
import threading


class Interface(Cmd):
    Coyote = Coyote()
    CoyoteThread = None
    stop_event = None
    promptBase = "COYOTE"
    prompt = "\n\033[1m\033[31m" + promptBase + " >\033[0m "
    intro = """\n\033
        .d8888b.                             888            
        d88P  Y88b                            888            
        888    888                            888            
        888         .d88b.  888  888  .d88b.  888888 .d88b.  
        888        d88""88b 888  888 d88""88b 888   d8P  Y8b 
        888    888 888  888 888  888 888  888 888   88888888 
        Y88b  d88P Y88..88P Y88b 888 Y88..88P Y88b. Y8b.     
         "Y8888P"   "Y88P"   "Y88888  "Y88P"   "Y888 "Y8888  
                                 888                         
                            Y8b d88P                         
                             "Y88P"      
    \033[0m"""

    def __init__(self):
        Cmd.__init__(self)

    ### TOOLBOX ###
    def hexToStr(self, hexstr):
        string = hexlify(hexstr).decode('ascii')
        return string[:2] + ":" + string[2:4] + ":" + string[4:6] + ":" + string[6:8] + ":" + string[
                                                                                              8:10] + ":" + string[-2:]

    def strToHex(self, string):
        hexes = string.split(":")
        hexstr = ''.join(hexes).encode("ascii")
        return unhexlify(hexstr)

    def changeRunningState(self, state):
        if state == True:
            self.prompt = "\n\033[1m\033[32m" + self.promptBase + " >\033[0m "
            self.Coyote.isRunning = True
        elif state == False:
            self.prompt = "\n\033[1m\033[31m" + self.promptBase + " >\033[0m "
            self.Coyote.isRunning = False

    def do_create_virtual_tap(self, s):
        self.Coyote.createTap()

    def help_create_virtual_tap(self):
        print("Creates the virtual tap for Coyote core module")

    def do_destroy_virtual_tap(self, s):
        self.Coyote.downTap()

    def help_destroy_virtual_tap(self):
        print("Deletes the virtual tap for Coyote core module")

    def do_show(self, argString):
        args = argString.split()
        if len(args) != 1:
            print("*** Invalid number of arguments")
            self.help_show()
        else:
            if args[0] == "tap" and self.Coyote.tap != None:
                print("tap :")
                print("Address ===> " + self.Coyote.tap.addr)
                print("MAC ===> " + self.hexToStr(self.Coyote.tap.hwaddr))
                print("mtu ===> " + str(self.Coyote.tap.mtu))
            elif args[0] == "host_ip" and self.Coyote.hostip != None:
                print("host_ip ===> " + self.Coyote.hostip)
            elif args[0] == "host_mac" and self.Coyote.hostmac != None:
                print("host_mac ===> " + self.Coyote.hostmacStr)
            elif args[0] == "rules":
                if self.Coyote.CoyoteFangs.ruleCount == 0:
                    print("No rule added (yet)")
                else:
                    num = 0
                    for rule in self.Coyote.CoyoteFangs.userRules:
                        num += 1
                        print("Rule " + str(num) + " : \n\tport = " + str(
                            rule.dst_port) + "\n\ttype = " + rule.type + "\n\tproto = " + rule.proto)
            elif args[0] == "netIface":
                print("netIface ===> " + self.Coyote.switchIface)
            elif args[0] == "hostIface":
                print("hostIface ===> " + self.Coyote.LhostIface)
            elif args[0] == "all":
                self.do_show("tap")
                self.do_show("host_ip")
                self.do_show("host_mac")
                self.do_show("hostIface")
                self.do_show("netIface")
                self.do_show("rules")

    def help_show(self):
        print("USAGE : show <attribute>")

    def complete_show(self, match, line, bindex, eindex):
        COMPLETION_ARRAY = ('tap', 'host_ip', 'host_mac', 'rules', 'hostIface ', 'netIface ', 'all')
        return [i for i in COMPLETION_ARRAY if i.startswith(match)]

    def do_set(self, argString):
        args = argString.split()
        if len(args) != 2:
            print("*** Invalid number of arguments")
            self.help_set()
        else:
            if args[0] == "debug":
                Cmd.do_set(self, argString)
            elif args[0] == "host_mac":
                attrValue = self.strToHex(args[1])
            else:
                attrValue = args[1]
            if not self.Coyote.setAttribute(args[0], attrValue):
                print("*** Invalid argument")
                self.help_set()
            else:
                print(args[0] + " ===> " + args[1])

    def help_set(self):
        print("USAGE : set <attribute> <value>")
        print("Attributes = host_ip, host_mac, netIface, hostIface, verbosity <0-3>")

    def complete_set(self, match, line, bindex, eindex):
        COMPLETION_ARRAY = ('host_ip ', 'host_mac ', 'verbosity ', 'netIface ', 'hostIface ')
        if bindex == 4:
            return [i for i in COMPLETION_ARRAY if i.startswith(match)]
        else:
            return ('')

    def do_stats(self, s):
        if self.Coyote.isRunning == True:
            print("Packet(s) processed by Coyote : " + str(self.Coyote.pktsCount))

    def do_add_reverse_rule(self, argString):
        args = argString.split()
        if len(args) != 3:
            print("*** Invalid number of arguments")
            self.help_add_rule()
        else:
            try:
                args[0] = int(args[0])
            except:
                print("*** First agument must be a number")
                self.help_add_rule()
            TYPES_ARRAY = ('unique', 'multi')
            if args[0] <= 65535 and args[0] > 0 and args[1] in TYPES_ARRAY:
                self.Coyote.CoyoteFangs.addRule(args[0], args[2], args[1])
                print(
                    "New rule added : \n\tport = " + str(args[0]) + "\n\ttype = " + args[1] + "\n\tproto = " + args[2])
            else:
                print("*** Invalid arguments")
                self.help_add_rule()

    def help_add_reverse_rule(self):
        print("USAGE : add_reverse_rule <port> <type = unique> <proto = IP>")
        print(
            "Interface for adding port-specific rules to allow reverse connection to reach Coyote. This is useful for reverse shell or for server-based exploits & fun (Responder)")
        print(
            "Types include : \n\tunique = rule is triggered once before being deleted (useful to get a reverse shell from one host) \n\tmulti = rule can be triggered multiple times (useful for MitM stuff)")

    def complete_add_reverse_rule(self, match, line, bindex, eindex):
        if bindex <= 16:
            return (' ')
        elif bindex > 16:
            if line.count(' ') == 2:
                COMPLETION_ARRAY = ('unique ', 'multi ')
                return [i for i in COMPLETION_ARRAY if i.startswith(match)]
            elif line.count(' ') >= 3:
                return ('')
            else:
                return ('')
        else:
            return ('')

    def do_autoconf(self, s):
        print("Running initAutoconf...")
        self.Coyote.initAutoconf()
        self.do_show('all')

    def help_autoconf(self):
        print("Runs the auto-configuration module")

    def do_run(self, s):
        if self.Coyote.tap == None:
            self.do_create_virtual_tap("")
        if self.Coyote.tap != None and self.Coyote.hostip != '' and self.Coyote.hostmac:
            self.Coyote.setAttribute("verbosity", 0)
            self.changeRunningState(True)
            self.stop_event = threading.Event()
            self.CoyoteThread = threading.Thread(target=self.Coyote.initMANGLE, args=(self.stop_event,))
            self.CoyoteThread.daemon = True
            self.CoyoteThread.start()
        #			self.Coyote.initMANGLE()
        else:
            print("*** Coyote PANIC : Configuration problem")
            self.help_run()

    def help_run(self):
        print("USAGE : run")
        print("This will launch Coyote core in a new thread and remove any verbosity !")
        print(
            "(Disclaimer : you must have run the auto-configuration module or given correct information manually before running this command ! You need at least host_ip, host_mac and a virtual tap created !)")

    def do_run_debug(self, s):
        if self.Coyote.tap == None:
            self.do_create_virtual_tap("")
        if self.Coyote.tap != None and self.Coyote.hostip != '' and self.Coyote.hostmac:
            self.changeRunningState(True)
            self.stop_event = threading.Event()
            self.Coyote.initMANGLE(self.stop_event)
        else:
            print("*** Coyote PANIC : Configuration problem")
            self.help_run_debug()

    def help_run_debug(self):
        print("USAGE : run_debug")
        print("This will launch Coyote core WITHOUT creating a new thread !")
        print(
            "(Disclaimer : you must have run the auto-configuration module or given correct information manually before running this command ! You need at least host_ip, host_mac and a virtual tap created !)")

    def do_stop(self, s):
        if self.Coyote.isRunning == True:
            self.stop_event.set()
            self.CoyoteThread.join()
            self.changeRunningState(False)
            print("Coyote was stopped")
        else:
            print("Coyote is not running at the moment...")

    def help_stop(self):
        print("Stops the Coyote thread")

    def do_cookie(self, s):
        print("This cookie machine is brought to you by Valérian LEGRAND valerian.legrand@orange.com\n")
        print("COOKIE COOKIE COOKIE")
        print("COOKIE COOKIE COOKIE")
        print("COOKIE COOKIE COOKIE")
        print("COOKIE COOKIE COOKIE")
        print("COOKIE COOKIE COOKIE")

    def do_exit(self, s):
        return True

    def do_help(self, s):
        if s == '':
            print("Coyote Commands :")
            print("\tcookie")
            print("\tcreate_virtual_tap")
            print("\tdestroy_virtual_tap")
            print("\tadd_reverse_rule")
            print("\trun")
            print("\trun_debug")
            print("\tset")
            print("\tshell")
            print("\tshortcuts")
            print("\tautoconf")
            print("\tstop")
            print("\tquit")
            print("\thelp")
        else:
            Cmd.do_help(self, s)

    def complete_help(self, match, line, bindex, eindex):
        COMPLETION_ARRAY = (
            'cookie', 'create_virtual_tap', 'destroy_virtual_tap', 'add_reverse_rule', 'run', 'run_debug', 'set',
            'shell',
            'shortcuts', 'autoconf', 'stop', 'quit', 'exit', 'help')
        return [i for i in COMPLETION_ARRAY if i.startswith(match)]


if __name__ == '__main__':
    app = Interface()
    app.cmdloop()
