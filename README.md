# Two-Face

## 1. Install emp-zk:

wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py<br>
python3 install.py --deps --tool --ot --zk

## 2. Build project

mkdir build<br>
cd build<br>
cmake ..<br>
make<br>
./twoface Sa [threads] [timeout_sec]<br>
./twoface Sb [threads] [timeout_sec]<br>
./twoface C<br>

## Notes

Sa stands for Server a, Sb stands for Server b, C stands for the client.

Number of messages on the board (N), number of pertinent signals (P), and ip of the two servers, can be modified in util.h.

`threads` is the size of the worker pool (default 1). `timeout_sec` is how long a party waits for the others before it stops (default 600, 0 waits forever); the client takes it as its third argument too. A party that detects a failed check, malformed data, a timeout or a lost connection prints the reason and exits with status 2, and the others stop when its connections close.

