# EMP-ZK Setup Instructions

## 1. Install emp-zk:

wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py
python3 install.py --deps --tool --ot --zk

## 2. Build project

mkdir build
cd build
cmake ..
make
./twoface Sa
./twoface Sb
./twoface C

## Notes

Sa stands for Server a, Sb stands for Server b, C stands for the client.

Number of messages on the board - N, number of pertinent signals - P, and ip of two servers, can be modified in util.h.

