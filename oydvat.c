#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h> // For sleep() if needed

typedef struct {
    const char *url;
    const char *threat_name;
    const char *threat_description;
} ThreatEntry;

static ThreatEntry blacklisted_videos[] = {
    { "https://www.youtube.com/shorts/7LocaReldQY", "OYDVAT:CrimeA:Kidnapping", "Kidnapping: Crime where the criminal takes away a victim..." },
    { "https://www.youtube.com/shorts/JeMUSXGaGkE", "OYDVAT:CrimeB:EncouragementToBuyBannedThings", "Encourages users to buy items that are illegal or banned." },
    { "https://www.youtube.com/shorts/Q8JSJGLthg8", "OYDVAT:Deception:DoWare", "Deceptive video tricking users into interacting." },
    { "https://www.youtube.com/shorts/BWX10-Y5Uck", "OYDVAT:Stealer:PersonalInfoLeaker", "Tries to make users leak sensitive info." },
    { "https://www.youtube.com/shorts/xrlayKFSNGw", "OYDVAT:OYDVAT:FromBlacklistedCreator", "Video from a blacklisted creator." },
    { "https://www.youtube.com/shorts/hRBrAic7PI8", "OYDVAT:CrimeA:MakingKidsArrested", "Tries to encourage kids to steal." },
    { "https://www.youtube.com/shorts/wPl_ERomUfQ", "OYDVAT:Children:ChildAbuse", "Abuses children for views, likes, etc." }
};

static const int THREAT_COUNT = sizeof(blacklisted_videos) / sizeof(blacklisted_videos[0]);

static int contains_case_insensitive(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;
    return strcasestr(haystack, needle) != NULL;
}

static void check_browser(const char *browser_pattern) {
    if (!browser_pattern) return;

    // Linux: Use 'ps' to get PID, executable name (comm), and full command line (args)
    // -e: all processes, -o: custom format
    FILE *pipe = popen("ps -eo pid,comm,args --no-headers", "r");
    if (!pipe) {
        printf("OYDVAT LOG: Failed to run process enumeration (ps).\n");
        return;
    }

    char line[16384];
    int any_browser_found = 0;

    while (fgets(line, sizeof(line), pipe)) {
        char pid[16], comm[256], args[16128];
        
        if (sscanf(line, "%15s %255s %[^\n]", pid, comm, args) >= 2) {
            
            if (contains_case_insensitive(comm, browser_pattern) || 
                contains_case_insensitive(args, browser_pattern)) {
                
                any_browser_found = 1;
                printf("OYDVAT LOG: Detected process [%s] (PID: %s). Scanning...\n", comm, pid);

                int threat_found = 0;
                for (int i = 0; i < THREAT_COUNT; ++i) {
                    if (contains_case_insensitive(args, blacklisted_videos[i].url)) {
                        threat_found = 1;
                        printf("\n!!! THREAT DETECTED !!!\n");
                        printf("Threat: %s\n", blacklisted_videos[i].threat_name);
                        printf("Description: %s\n", blacklisted_videos[i].threat_description);
                        printf("Action: Terminating PID %s\n", pid);

                        char kill_cmd[64];
                        snprintf(kill_cmd, sizeof(kill_cmd), "kill -9 %s > /dev/null 2>&1", pid);
                        system(kill_cmd);
                        break; 
                    }
                }
                if (!threat_found) {
                    printf("No threat detected in process %s.\n", pid);
                }
            }
        }
    }
    pclose(pipe);
}

int main(void) {
    printf("Welcome to OYDVAT (Linux Version)\n");
    printf("Protecting against harmful YouTube videos...\n\n");

    for (;;) {
        // Linux browser process names are usually lowercase
        check_browser("chrome");
        check_browser("firefox");
        check_browser("msedge");
        check_browser("brave");
        check_browser("opera");
        check_browser("yt-dlp");
    }

    return 0;
}
