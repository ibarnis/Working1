import os
import stat

# specify the path to the file you want to protect
path=r"C:\Users\User\Documents\cyber\project\enc_whitelist.db"

# set read-only permissions for all users
os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)