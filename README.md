# Shivam Patel
## Federated Election Count
### Federated Election Count Protocol (FEC Protocol) is a fault tolerant election counting network protocol that runs ontop of the transport layer, It works by having the hosts dump FEC packets onto the network that encode votes of the network portion they govern, the networking hardware then assists in counting and removing of duplicates.  The end result is, that all of the hosts(who them selves were the representatives of other hosts) come to consensus about the outcome of an election without having to have directly communicated with one another

To Run please complete the following steps.
(1). In Hangar, extract the FederatedElectionCount.zip file.

(2). Move the directory to ~/Hangar/networks and cd into ~/Hangar/networks/FederatedElectionCount

(3). Test data is ready (it exists in regionalCSVs, in the 5 regional directorys)

(4). To Create more test cases aside from the 1, all is required is to edit the 
"optional_add/"optional_remove" dictionarys by appending "XX:XX:XX..." where XX are state abbreviations, but it will require to run pip3 install pandas;pip3 install networkx

(5). This is unfortunate but the make file in the main directory ~/Hangar will need to be replaced with the one in special_p4.  Similar thing with the lib directory.  So please run "rm ~Hangar/Makefile;rm -r ~/Hangar/lib" followed by "cp special_p4/Makefile ~/Hangar;cp -r special_p4/lib ~/Hangar"

(6). Then cd ~/Hangar and run make.  Then cd back to networks/FederatedElectionCount

(7). For your conveneince there is a file named run.sh which contains the command to run it in interactive mode "HANGARGAMES=/home/vagrant/Hangar/ MODE=interactive ~/Hangar/networks/FederatedElectionCount/FederatedElectionCount.sh" while in the FederatedElectionCount directory(you need to be in that directory because the python code depends on directorys in there, and for some reason the paths were not well behaves relative to ~Hangar so they had to be made relative to FederatedElectionCount)

(8). Now with mininet up, you will need to create 10 additional screens and in the current one do:

b1 create_screen 'b1'
h1 create_screen 'h1'
h2 create_screen 'h2'
h3 create_screen 'h3'
h4 create_screen 'h4'
h5 create_screen 'h5'
b1 create_screen 'b1'
c1 create_screen 'c1'
m1 create_screen 'm1'
m2 create_screen 'm2'
m3 create_screen 'm3'

(9). then in i+1th screen you need to do do "sudo attach_screen XX" where XX is one of the hosts.  And in order, you need to have typed ready the following, but dont run them right away

./broadcast.py (in b1's screen)
./runRegion.py MidWest (in h1's screen... etc,i wont type more so you can copy paste)
./runRegion.py South 
./runRegion.py West 
./runRegion.py PacificNorthWest
./runRegion.py NewEngland
./runRegion.py Citizen
./runRegion.py Legislature1
./runRegion.py Legislature2
./runRegion.py Legislature3

(10). if you ran ./run.sh from within FederatedElectionCount and created your screens from the screen that mininet appeared in.  You're now ok to begin pressing enter on all the screens you typed in the previous lines.  you have about 10 seconds to hit all 10, the threads that send their chunks of the file sleep for 10 seconds to allow for the others to be activated.  

(11). If everything went well, what you'll see is b1's screen(the one running broadcast.by) spitting out a bunch of statements about what its received and whats its sending.  As well youll see results and counts slowly start to flood into the 5 regions and the citizen observer, as well as the host hooked up to the legislative switches printing what it saw as well(I needed to do this because otherwise there were problems with UDP, in particular protocol missing style errors.  The switch s2-s4 that are actually Legislature1-3, in particular they handle marking seen packets and dropping repeats from replica votes that exist on multiple hosts)

(12).  The project was about an 80% success in the sense that thats on average how relaible the packet delivery is.  Due to me needing sniffing and sending on the same host, I decided to use threads.  In particular the packet handlers fork a thread to do a send.  The issue is, they were so fast that only 30% of the packets made it through.  When i added a sleep of 1 second per send on everyhost, it changed to about 80% packet arrival/sending properly.  Actually whats interesting is, since its child threads who do the sending and modifying of a records keeping datastructure, as well as some mininet quirk, they print their real counts on the terminal and etc as theyre running, but if you try to print a given ./runRegion.py output to a log like with >, then there is a lesser amount of data that shows.  For example many of the hosts will show up to 48-49 received votes out of 50 when running normally in the screen, but if you attempt to "./runRegion X > X.txt", there wil be a mismatch with what was just observed.  My hypothesis is that this is due to the GIL in python, as well as a mininet quirk, and as well as my poor attempt at doing poor mans client-server.  But fortunately we can see in the pcap and s1, s2-4 log files for the switches.  That the p4 code is running proper and doing what it does keeping state and dropping seen packets and doing switching/routing.  So i feel the loss of packets is coming from the thread stuff, as well as maybe it being too much for mininet to handle.  
