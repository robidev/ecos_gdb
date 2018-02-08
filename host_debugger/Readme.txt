Dependencies:
------------
CMake(for keystone-engine)
Keystone enigne
Capstone engine
pyserial.

Installation:
------------
sudo apt-get install cmake
sudo apt-get install python-pip
sudo apt-get install libcapstone3
sudo apt-get install keystone
sudo pip install pyserial
sudo pip install capstone
sudo pip install keystone-engine

python nano_debug.py

Testing
-------
sertest.py is a tool to test the serial interface. it emulates the way the debug interface responds.
it echos the address values back as data-values

to start sertest.py as a test-application for nano_debug, enter 'socat -d -d pty,raw,echo=0 pty,raw,echo=0', 
and the 2 endpoints are echod in the terminal as /dev/pts/x and /dev/pts/x
