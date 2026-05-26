# GRUBS

- ☐ When the user management screen loads for the first time, disabled users are shown despite the filter being set (visually at least) to hiding disabled users.
- ☐ We see a lock release success and then an immediate failure on the same PID.
```
[2025-09-02 19:42:40,396] [locking.py:107] [MainThread] [351431] [INFO] - released lock on b18d83f7-c08e-40b0-a434-4eddd5a26793
[2025-09-02 19:42:40,397] [locking.py:109] [MainThread] [351431] [WARNING] - failed to release lock on b18d83f7-c08e-40b0-a434-4eddd5a26793 with lock uuid 75a92cd0-7beb-4b57-8127-07ebfa767af3
```
- ☐ The yara scanner is still logging twice. Also missing time to scan metrics.