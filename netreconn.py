# library to access linux commands
import os
import subprocess
import time
import sys
ipaddress = ""
ports = ""

def is_running_as_sudo():
    return os.geteuid() == 0

def ipadd():
    global ipaddress
    temp_ipaddress = str(input("Enter ip address of host ["  + ipaddress + "]:"))
    if len(temp_ipaddress) > 0:
       ipaddress = temp_ipaddress
    print(ipaddress)
    return ipaddress


def iface():
    interface = str(input("Enter interface name[eth0]: "))
    if len(interface) == 0:
        interface = "eth0"
    print(interface)
    return interface


def url():
    urll = str(input("Enter url of target :"))
    return urll


def subnet():
    ipsubnet = str(input("Enter IP Subnet: "))
    return ipsubnet


def enum():
    os.system("enum4linux -a " + ipadd())


def john():
    print("Running John the Ripper")
    print("Assuming file:key has been created")
    print("Creating file:hash from file:key using john:")
    os.system("ssh2john key > hash")
    print("Cracking password from file:hash using rockyou.txt")
    os.system("john -w=/usr/share/wordlists/rockyou.txt hash")
    print("With this private key password, you now can use it on key on [ssh -i key user@host]")
    print(" goto http://unix4lyfe.org to generate Hash")


def fuzz():
    os.system("ffuf -u http://" + url() + "/FUZZ" + " -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt")

def port():
    temp_port = input("Enter port [80] :")
    if len(temp_port) == 0:
        ports = "80"
    else:
        ports = temp_port
    print(ports)
    return ports

def nikto():
    #ipa = input("Enter IP address: ")
    #os.system("nikto -C all -h " + ipa)
    command = "nikto -C all -h " + ipadd() + " -p " + port()
    print("Excuting the following command")
    print("\033[91m" + f"{command}")
    os.system(command)
    print("\033[0m")

def dirb():
    choice = input("[1] = http\n[2] = https\nEnter choice: ")
    if choice == "1":
        os.system("dirb http://" + url() + ":" + port() + "/")
    elif choice == "2":
        os.system("dirb https://" + url() + ":" + port() + "/")
    else:
        print("Invalid choice")

def gobust():
    choice = input("[1] = http\n[2] = https\nEnter choice: ")
    if choice == "1":
        os.system("gobuster -u http://" + url() + "/" + " -w /usr/share/wordlists/dirb/common.txt dir")
    elif choice == "2":
        os.system("gobuster -u https://" + url() + "/" + " -w /usr/share/wordlists/dirb/common.txt dir")
    else:
        print("Invalid choice")

def harvester():
    os.system("theHarvester -l 500 -d " + ipadd() + " -b google")

def is_running_as_sudo():
    return os.geteuid() == 0

def ipadd():
    global ipaddress
    temp_ipaddress = str(input("Enter ip address of host ["  + ipaddress + "]:"))
    if len(temp_ipaddress) > 0:
       ipaddress = temp_ipaddress
    print(ipaddress)
    return ipaddress


def iface():
    interface = str(input("Enter interface name[eth0]: "))
    if len(interface) == 0:
        interface = "eth0"
    print(interface)
    return interface


def url():
    urll = str(input("Enter url of target :"))
    return urll


def subnet():
    ipsubnet = str(input("Enter IP Subnet: "))
    return ipsubnet


def enum():
    os.system("enum4linux -a " + ipadd())


def john():
    print("Running John the Ripper")
    print("Assuming file:key has been created")
    print("Creating file:hash from file:key using john:")
    os.system("ssh2john key > hash")
    print("Cracking password from file:hash using rockyou.txt")
    os.system("john -w=/usr/share/wordlists/rockyou.txt hash")
    print("With this private key password, you now can use it on key on [ssh -i key user@host]")
    print(" goto http://unix4lyfe.org to generate Hash")


def fuzz():
    os.system("ffuf -u http://" + url() + "/FUZZ" + " -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt")

def nikto():
    #ipa = input("Enter IP address: ")
    #os.system("nikto -C all -h " + ipa)
    command = "nikto -C all -h " + ipadd() + " -p " + port()
    print("Excuting the following command")
    print("\033[91m" + f"{command}")
    os.system(command)
    print("\033[0m")

def dirb():
    choice = input("[1] = http\n[2] = https\nEnter choice: ")
    if choice == "1":
        os.system("dirb http://" + url() + ":" + port() + "/")
    elif choice == "2":
        os.system("dirb https://" + url() + ":" + port() + "/")
    else:
        print("Invalid choice")

def gobust():
    choice = input("[1] = http\n[2] = https\nEnter choice: ")
    if choice == "1":
        os.system("gobuster -u http://" + url() + "/" + " -w /usr/share/wordlists/dirb/common.txt dir")
    elif choice == "2":
        os.system("gobuster -u https://" + url() + "/" + " -w /usr/share/wordlists/dirb/common.txt dir")
    else:
        print("Invalid choice")

def harvester():
    os.system("theHarvester -l 500 -d " + ipadd() + " -b google")

#temp
def hydra():
    service = input("Enter service ssh/telnet/wpa/ftp :")
    if service != "wpa":
        loginname = input("Enter username or enter X to use user.txt :")
        password = input("Enter password or enter X to use pass.txt or R to use rockyou.txt :")
        if ((loginname != "X") or (loginname != "x")):
            command = "echo " + loginname + " > user.txt"
            os.system(command)
            print(f"{command}")
        if len(password) > 1:
            command = "echo " + password + " > pass.txt"
            os.system(command)
            print(f"{command}")
        elif password.upper() == "X":
           print("Using pass.txt")
        if password.upper() == "R":
            command = "cp /usr/share/wordlists/rockyou.txt pass.txt"
            os.system(command)
            print(f"{command}")
        command = "hydra -t 4 -L user.txt -P pass.txt -vV " + ipadd() + " " + service + " -s " + port()
        print(f"{command}")
        os.system(command)
    else:
        loginname = input("Enter username or enter X to use user.txt :")
        password = input("Enter password or enter X to use pass.txt :")
        if ((loginname == "X") or (loginname == "x")) and (password == "X" or password == "x"):
            command =  "hydra -L user.txt -P pass.txt " + ipadd() + " http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username'"
            print(f"{command}")
            os.system(command)
        elif ((loginname == "X" or loginname == "x") and (password != "X" or password != "x")):
            command = "echo " + password + " > pass.txt"
            print(f"{command}")
            os.system(command)
            command = "hydra -L user.txt -P pass.txt " + ipadd() + " vm http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=is incorrect'"
            print(f"{command}")
            os.system(command)
        else:
            command = "echo " + loginname + " > user.txt"
            print(f"{command}")
            os.system(command)
            command = "hydra -L user.txt -P pass.txt " + ipadd() + " http-post-form '/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=is incorrect'"
            print(f"{command}")
            os.system(command)

def smbclient():
    command = "smbclient -L " + ipadd()
    print(f"{command}")
    os.system(command)

def nmap():
    ques = input("Would you like to save to a file [y/n]: ")
    if ques.lower() == "y":
        filename = input("Enter filename: ")
    else:
        filename = "results.xml"
    # ipadd = input("Enter ip address of host: ")
    os.system("sudo nmap -p- -sC -sV -oX " + filename + " " + ipadd())
    ques2 = input("Would like you like to see result firefox [y/n]: ")
    if ques2 == "y" or ques2 == "Y":
        os.system("xsltproc " + filename + " -o temp.html")
        os.system("firefox " + "temp.html")


def nmap2():
    ques = input("Would you like to save to a file [y/n]: ")
    if ques.lower() == "y":
        filename = input("Enter filename: ")
    else:
        filename = "results.xml"
    command = "sudo nmap -p- -sC -sV -oX " + filename + " " + ipadd()
    # Echo Command
    print("Executing\n", command)
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Print dots while the command is running
    while process.poll() is None:
        print("\r|", end="", flush=True)
        time.sleep(0.5)
        print("\r/", end="", flush=True)
        time.sleep(0.5)
        print("\r-", end="", flush=True)
        time.sleep(0.5)
        print("\r\\", end="", flush=True)
        time.sleep(0.5)
    # Capture and decode the command output
    output, error = process.communicate()
    output = output.decode("utf-8")
    # Print the final result
    print("\nResult:")
    print(output)
    ques2 = input("Would like you like to see result firefox [y/n]: ")
    if ques2.lower() == "y":
        os.system("xsltproc " + filename + " -o temp.html")
        os.system("firefox " + "temp.html")





# function data creates user.txt and pass.txt
def userpass():
    counter = 1  # count how many words inputed
    keylist = []  # init variables
    new_list = ''
    new_keylist = []
    pass_list = []
    # start loop to keep adding words
    while True:
        keyword = input("Enter keyword, x to stop\n")
        # if user exits without entering data then stop
        if (keyword == "x") and (counter == 1):
            print("\nExit no words entered\n")
            break
        # check if user has finished entering data
        if (keyword == "x") and (counter != 1):
            print("Creating user.txt and pass.txt")
            # calculate how many entries
            count = len(keylist) - 1
            print(str(count + 1) + " words created.")
            # store each word temporarily
            templist = list(keylist)
            # repeat words in the last
            for i in range(count):
                keylist.extend(templist)
            # print(keylist) used for testing
            new_data = open("/home/kali/recon/test.txt", "w")
            # convert list to text
            for x in new_keylist:
                new_list += str(x) + '\n'
            new_data = open("/home/kali/recon/user.txt", "w")
            # add new line to each name
            for x in keylist:
                new_list += x + '\n'
            # print(new_list) used for testing
            # save data to file
            new_data.write(str(new_list))
            # create pass.txt
            for y in range(count + 1):
                for z in range(count + 1):
                    pass_list.append(keylist[y])
            # print(pass_list) used for testing
            # convert list to text
            # re-intialize list
            new_list = ''
            for x in pass_list:
                new_list += str(x) + '\n'
            new_data = open("/home/kali/recon/pass.txt", "w")
            # save data to file
            new_data.write(str(new_list))
            break
        # add new word to list
        keylist.append(keyword)
        # increment counter
        counter += 1


# converts text file to binary
# input to function is the data to be converted
def convert2binary(data1):
    # convert to binary file
    savefile = input("Name of file to save: ")
    file_bytearray = bytearray.fromhex(data1)
    # save contents to *.jpg
    new_file = open("/home/kali/recon/" + savefile, "wb")
    new_file.write(file_bytearray)
    print("File saved as " + savefile)
    print("File type of converted file....")
    os.system("file " + savefile)

def unshadow():
    passwd_temp = str(input("enter filename of passwd [passwd]:"))
    if len(passwd_temp) > 0:
        passwd = passwd_temp
    else:
         passwd = "passwd"
    shadow_temp = str(input("enter filename of shadow [shadow]:"))
    if len(shadow_temp) > 0:
         shadow = shadow_temp
    else:
         shadow = "shadow"
    command = "unshadow " + passwd + " " + shadow + " > mypass.txt"
    command2 = "john --wordlist=/usr/share/wordlists/rockyou.txt mypass.txt"
    print(f"{command}")
    os.system(command)
    print(f"{command2}")
    os.system(command2)

# function that loads the file to be converted
# and performs checks
def hexconvert():
    filename = input("Enter name of suspect /dir/file: ")
    if not (os.path.exists(filename)):
        print("File does not exist")
        return
    print("File type of suspect file...")
    os.system("file " + filename + "\n")
    with open('/home/kali/recon/' + filename, 'r') as file:
        data = file.read()
    # Check to see if file contains 0x
    first_two = data[:2]
    if (first_two == "0x"):
        print("Removing 0x, commas and spaces")
        # remove 0x
        data = data.replace("0x", "")
        # remove white spaces
        data = ''.join(data.split())
        # remove comma seperators
        data = data.replace(',', '')
        convert2binary(data)
    else:
        # 0x NOT present just remove spaces")
        print("Removing spaces")
        data = ''.join(data.split())
        convert2binary(data)


# function that performs arp-scan and linux
# enter subnet
def arpscan():
    result = os.system("echo kali | sudo arp-scan --interface=" + iface() + " " + subnet())
    print("Success! ")
    print(result)
    pause_1  = input("Press any ENTER to continue")

# Function that downloads files from given host
def webcrawl():
    command = "wget -r --no-parent -R 'index.html*' http://" + ipadd()
    print(f"Excuting following command\n {command}")
    os.system(command)
    print("\nSuccess! ")
    print("\nFiles are stored under directory named " +  ipaddress + "\n")
    os.system("ls -la ./" + ipaddress )

def dnsrecon():
    command = "dnsrecon -t brt -d " + url()
    print(f"{command}")
    os.system(command)

def banner():
    print("\n")
    print(" _ __   ___| |_ _ __ ___  ___ ___  _ __  _ __  ")
    print("| '_ \ / _ \ __| '__/ _ \/ __/ _ \| '_ \| '_ \ ")
    print("| | | |  __/ |_| | |  __/ (_| (_) | | | | | | |")
    print("|_| |_|\___|\__|_|  \___|\___\___/|_| |_|_| |_|")
    print("\n")


# Main menu
banner()
#if not is_running_as_sudo():
#   print("Please run as sudo")
#   sys.exit(1)

while True:
    print("##########################")
    print("# Network Reconnaissance #")
    print("##########################")
    print("[1] Scan devices on subnet")
    print("[2] Webcrawl download files")
    print("[3] Convert files to binary")
    print("[4] Create username password files")
    print("[5] nmap (scan 4 open ports")
    print("[6] hydra (password cracker)")
    print("[7] smbclient (find samba shares)")
    print("[8] theHarvester (get info)")
    print("[9] dirbuster (find directories")
    print("[A] FUZZ")
    print("[B] nikto (web vulnerability")
    print("[C] JohnTR")
    print("[D] Enum4linux")
    print("[E] gobuster (Hidden webpages")
    print("[F] dnsrecon (find subdomains")
    print("[G] Unshadow Password File Linux")
    print("[X] to exit")
    ans = input("Input your selection :")
    if (ans == "1"):
        arpscan()
    elif (ans == "2"):
        webcrawl()
    elif (ans == "3"):
        hexconvert()
    elif (ans == "4"):
        userpass()
    elif (ans == "5"):
        nmap2()
    elif (ans == "6"):
        hydra()
    elif (ans == "7"):
        smbclient()
    elif (ans == "8"):
        harvester()
    elif (ans == "9"):
        dirb()
    elif ans.upper() == "A":
        fuzz()
    elif ans.upper() == "B":
        nikto()
    elif ans.upper() == "C":
        john()
    elif ans.upper() == "D":
        enum()
    elif ans.upper() == "E":
        gobust()
    elif ans.upper() == "F":
        dnsrecon()
    elif ans.upper() == "G":
        unshadow()
    elif ans.lower() == "x":
        print("Goodbye")
        break
    else:
        print("Invalid entry")
