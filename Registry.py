import hashlib
import winreg

# Define the keys to be hashed
keys = [
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
]

# Create an empty dictionary to store the previous hashes
prev_hashes = {}

while True:
    # Open the file to save the current hashes
    with open("hashes.txt", "w") as f:
        for key in keys:
            try:
                # Open the key
                handle = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key)

                # Get the value of the key
                value = winreg.QueryValueEx(handle, None)[0]

                # Create a hash object
                sha256 = hashlib.sha256()

                # Hash the value of the key
                sha256.update(value.encode())

                # Write the hash to the file
                f.write(f"{key}: {sha256.hexdigest()}\n")

                # Close the key
                winreg.CloseKey(handle)

                # Compare the current hash with the previous hash
                if key in prev_hashes and sha256.hexdigest() != prev_hashes[key]:
                    print(f"ALERT: {key} has changed")

                # Update the previous hash
                prev_hashes[key] = sha256.hexdigest()
            except WindowsError:
                print(f"Error accessing key {key}")
    import time
    # wait for 1 min to check again the registry
    time.sleep(60)
