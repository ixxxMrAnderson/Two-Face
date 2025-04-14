# Two-Face

## 1. Install emp-zk:

wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py<br>
python3 install.py --deps --tool --ot --zk

## 2. Build project

mkdir build<br>
cd build<br>
cmake ..<br>
make<br>
./twoface Sa<br>
./twoface Sb<br>
./twoface C<br>

## Notes

Sa stands for Server a, Sb stands for Server b, C stands for the client.

Number of messages on the board (N), number of pertinent signals (P), and ip of the two servers, can be modified in util.h.

