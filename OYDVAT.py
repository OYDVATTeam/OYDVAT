import psutil
import os
import sys

print("Welcome to OYDVAT, or Official YouTube Dangerous Videos Abbreviation Tool")
print("This tool will help you protect against harmful videos that might sneak in YouTube")

blacklisted_videos = {
    "https://www.youtube.com/shorts/7LocaReldQY": {
        "threat_name": "OYDVAT:CrimeA:Kidnapping",
        "threat_description": "Kidnapping: Crime where the criminal takes away a victim, mostly kids, and demands payment or else harms the victim."
    },
    "https://www.youtube.com/shorts/JeMUSXGaGkE": {
        "threat_name": "OYDVAT:CrimeB:EncouragementToBuyBannedThings",
        "threat_description": "Encourages users to buy items that are illegal or banned in their country."
    },
    "https://www.youtube.com/shorts/Q8JSJGLthg8": {
        "threat_name": "OYDVAT:Deception:DoWare",
        "threat_description": "Deceptive video tricking users into interacting (like/comment/share), claiming bad things will happen if ignored."
    },
    "https://www.youtube.com/shorts/BWX10-Y5Uck": {
        "threat_name": "OYDVAT:Stealer:PersonalInfoLeaker",
        "threat_description": "Tries to make users leak sensitive info (like city name), which can lead to stalking or doxxing."
    },
    "https://www.youtube.com/shorts/xrlayKFSNGw": {
        "threat_name": "OYDVAT:OYDVAT:FromBlacklistedCreator",
        "threat_description": "The video is from a blacklisted creator. The creator has been blacklisted because it tricks users into interacting (like) with a specific body part, claiming getting cursed if ignored"
    }
}

def check(browser_name, blacklisted_dict):
    browser_processes_to_check = []
    
    try:
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                if proc.info['name'] and browser_name.lower() in proc.info['name'].lower():
                    browser_processes_to_check.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                print(f"OYDVAT LOG: Error accessing process information: {e}")
                continue
            except Exception as e:
                print(f"OYDVAT LOG: An unexpected error occurred: {e}")
                continue
                
        if browser_processes_to_check:
            print("OYDVAT LOG: Detected a browser process. Scanning it for blacklisted video links...")
            for proc in browser_processes_to_check:
                pid = proc.pid
                try:
                    cmdline_list = proc.info['cmdline']
                    cmdline_str = ' '.join(cmdline_list).lower()
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    print(f"OYDVAT LOG: Error accessing process command line: {e}")
                    continue
                except Exception as e:
                    print(f"OYDVAT LOG: An unexpected error occurred: {e}")
                    continue

                print("\nProcess info analysed.")
                print(f"Process Identifier: {pid}")
                print(f"Command Line: {' '.join(cmdline_list)}")
                print(f"Analyzing process {pid} for forbidden URLs...")

                threat_found = False

                for url, threat_info in blacklisted_dict.items():
                    if url.lower() in cmdline_str:
                        threat_name = threat_info['threat_name']
                        threat_description = threat_info['threat_description']
                        print(f"\nTHREAT DETECTED!")
                        print(f"Threat Name: {threat_name}")
                        print(f"Description: {threat_description}")
                        print(f"PID: {pid}")
                        print("The process will be terminated.")
                        try:
                            os.system(f"taskkill /f /pid {pid}")
                        except Exception as e:
                             print(f"OYDVAT LOG: Failed to terminate process {pid}: {e}")
                        threat_found = True
                        break  # Stop after first match

                if not threat_found:
                    print("No threat detected in this process.")
        else:
            print("Browser not open or not detected.")
    
    except Exception as e:
        print(f"OYDVAT LOG: An unexpected error occurred: {e}")

if __name__ == "__main__":
    while True:
        try:
            check("msedge.exe", blacklisted_videos)
            check("yt-dlp.exe", blacklisted_videos)
        except Exception as e:
            print(f"OYDVAT LOG: An unexpected error occurred in main: {e}")