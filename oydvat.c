#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

typedef struct {
    const char *url;
    const char *threat_name;
    const char *threat_description;
} ThreatEntry;

static ThreatEntry blacklisted_videos[] = {
    { "https://www.youtube.com/shorts/7LocaReldQY",
      "OYDVAT:CrimeA:Kidnapping",
      "Kidnapping: Crime where the criminal takes away a victim, mostly kids, and demands payment or else harms the victim." },
    { "https://www.youtube.com/shorts/JeMUSXGaGkE",
      "OYDVAT:CrimeB:EncouragementToBuyBannedThings",
      "Encourages users to buy items that are illegal or banned in their country." },
    { "https://www.youtube.com/shorts/Q8JSJGLthg8",
      "OYDVAT:Deception:DoWare",
      "Deceptive video tricking users into interacting (like/comment/share), claiming bad things will happen if ignored." },
    { "https://www.youtube.com/shorts/BWX10-Y5Uck",
      "OYDVAT:Stealer:PersonalInfoLeaker",
      "Tries to make users leak sensitive info (like city name), which can lead to stalking or doxxing." },
    { "https://www.youtube.com/shorts/xrlayKFSNGw",
      "OYDVAT:OYDVAT:FromBlacklistedCreator",
      "The video is from a blacklisted creator. The creator has been blacklisted because it tricks users into interacting (like) with a specific body part, claiming getting cursed if ignored" },
    { "https://www.youtube.com/shorts/hRBrAic7PI8",
      "OYDVAT:CrimeA:MakingKidsArrested",
      "Tries to encourage kids to steal, which can get them arrested." },
    { "https://www.youtube.com/shorts/wPl_ERomUfQ",
      "OYDVAT:Children:ChildAbuse",
      "Abuses children for views, likes, etc." }
};

static const int THREAT_COUNT = sizeof(blacklisted_videos) / sizeof(blacklisted_videos[0]);

// Convert string to lower-case into dest; dest must have space for src length + 1
static void to_lower_copy(const char *src, char *dest, size_t dest_size) {
    if (!src || !dest || dest_size == 0) return;
    size_t i = 0;
    while (src[i] != '\0' && i + 1 < dest_size) {
        dest[i] = (char)tolower((unsigned char)src[i]);
        i++;
    }
    dest[i] = '\0';
}

// Trim trailing and leading whitespace in-place
static void trim_inplace(char *s) {
    if (!s) return;
    // leading
    char *start = s;
    while (*start && isspace((unsigned char)*start)) start++;
    if (start != s) memmove(s, start, strlen(start) + 1);
    // trailing
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[len - 1] = '\0';
        len--;
    }
}

// Extract value for a prefix like "Name=" from block; returns dynamically allocated string (caller frees) or NULL
static char *extract_field_value(const char *block, const char *prefix) {
    if (!block || !prefix) return NULL;
    const char *pos = strstr(block, prefix);
    if (!pos) return NULL;
    pos += strlen(prefix);
    // read up to newline
    const char *end = strchr(pos, '\n');
    size_t len;
    if (end) len = end - pos;
    else len = strlen(pos);
    // Trim possible '\r' at end
    while (len > 0 && (pos[len - 1] == '\r' || pos[len - 1] == '\n')) len--;
    char *res = (char *)malloc(len + 1);
    if (!res) return NULL;
    memcpy(res, pos, len);
    res[len] = '\0';
    trim_inplace(res);
    if (res[0] == '\0') { free(res); return NULL; }
    return res;
}

static int contains_case_insensitive(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;
    size_t hlen = strlen(haystack), nlen = strlen(needle);
    if (nlen == 0) return 1;
    // lower-case copies
    char *hl = (char *)malloc(hlen + 1);
    char *nl = (char *)malloc(nlen + 1);
    if (!hl || !nl) {
        free(hl); free(nl);
        return 0;
    }
    to_lower_copy(haystack, hl, hlen + 1);
    to_lower_copy(needle, nl, nlen + 1);
    int found = (strstr(hl, nl) != NULL);
    free(hl); free(nl);
    return found;
}

static void check_browser(const char *browser_name) {
    if (!browser_name) return;

    // Run wmic and read process list in "LIST" format for easier parsing
    FILE *pipe = _popen("wmic process get CommandLine,Name,ProcessId /FORMAT:LIST", "r");
    if (!pipe) {
        printf("OYDVAT LOG: Failed to run process enumeration command (wmic).\n");
        return;
    }

    char line[8192];
    // Accumulate a block per process, separated by blank lines
    char block[65536];
    block[0] = '\0';
    int any_browser_found = 0;

    while (fgets(line, sizeof(line), pipe)) {
        // If line is just newline or carriage return, we finished a block
        if (strcmp(line, "\r\n") == 0 || strcmp(line, "\n") == 0) {
            // process current block
            if (block[0] != '\0') {
                char *name = extract_field_value(block, "Name=");
                char *pid = extract_field_value(block, "ProcessId=");
                char *cmdline = extract_field_value(block, "CommandLine=");
                if (name) {
                    // Compare process name with browser_name (case-insensitive, substring)
                    if (contains_case_insensitive(name, browser_name)) {
                        any_browser_found = 1;
                        printf("OYDVAT LOG: Detected a browser process. Scanning it for blacklisted video links...\n");
                        printf("\nProcess info analysed.\n");
                        printf("Process Identifier: %s\n", pid ? pid : "(unknown)");
                        printf("Command Line: %s\n", cmdline ? cmdline : "(none)");
                        printf("Analyzing process %s for forbidden URLs...\n", pid ? pid : "(unknown)");

                        int threat_found = 0;
                        if (cmdline) {
                            // check each blacklisted url
                            for (int i = 0; i < THREAT_COUNT; ++i) {
                                if (contains_case_insensitive(cmdline, blacklisted_videos[i].url)) {
                                    threat_found = 1;
                                    printf("\nTHREAT DETECTED!\n");
                                    printf("Threat Name: %s\n", blacklisted_videos[i].threat_name);
                                    printf("Description: %s\n", blacklisted_videos[i].threat_description);
                                    printf("PID: %s\n", pid ? pid : "(unknown)");
                                    printf("The process will be terminated.\n");
                                    if (pid) {
                                        char kill_cmd[256];
                                        _snprintf(kill_cmd, sizeof(kill_cmd), "taskkill /f /pid %s >nul 2>&1", pid);
                                        int rc = system(kill_cmd);
                                        if (rc != 0) {
                                            printf("OYDVAT LOG: Failed to terminate process %s (taskkill returned %d)\n", pid, rc);
                                        } else {
                                            printf("OYDVAT LOG: Successfully issued termination for PID %s\n", pid);
                                        }
                                    } else {
                                        printf("OYDVAT LOG: PID unknown, cannot terminate process.\n");
                                    }
                                    break; // stop after first match
                                }
                            }
                        }
                        if (!threat_found) {
                            printf("No threat detected in this process.\n");
                        }
                    }
                }
                free(name); free(pid); free(cmdline);
            }
            // reset block
            block[0] = '\0';
        } else {
            // add line to block (ensure we don't overflow)
            size_t cur = strlen(block);
            size_t to_copy = strlen(line);
            if (cur + to_copy + 1 < sizeof(block)) {
                strncat(block, line, sizeof(block) - cur - 1);
            }
        }
    }

    // Process any remaining block if file didn't end with blank line
    if (block[0] != '\0') {
        char *name = extract_field_value(block, "Name=");
        char *pid = extract_field_value(block, "ProcessId=");
        char *cmdline = extract_field_value(block, "CommandLine=");
        if (name) {
            if (contains_case_insensitive(name, browser_name)) {
                any_browser_found = 1;
                printf("OYDVAT LOG: Detected a browser process. Scanning it for blacklisted video links...\n");
                printf("\nProcess info analysed.\n");
                printf("Process Identifier: %s\n", pid ? pid : "(unknown)");
                printf("Command Line: %s\n", cmdline ? cmdline : "(none)");
                printf("Analyzing process %s for forbidden URLs...\n", pid ? pid : "(unknown)");

                int threat_found = 0;
                if (cmdline) {
                    for (int i = 0; i < THREAT_COUNT; ++i) {
                        if (contains_case_insensitive(cmdline, blacklisted_videos[i].url)) {
                            threat_found = 1;
                            printf("\nTHREAT DETECTED!\n");
                            printf("Threat Name: %s\n", blacklisted_videos[i].threat_name);
                            printf("Description: %s\n", blacklisted_videos[i].threat_description);
                            printf("PID: %s\n", pid ? pid : "(unknown)");
                            printf("The process will be terminated.\n");
                            if (pid) {
                                char kill_cmd[256];
                                _snprintf(kill_cmd, sizeof(kill_cmd), "taskkill /f /pid %s >nul 2>&1", pid);
                                int rc = system(kill_cmd);
                                if (rc != 0) {
                                    printf("OYDVAT LOG: Failed to terminate process %s (taskkill returned %d)\n", pid, rc);
                                } else {
                                    printf("OYDVAT LOG: Successfully issued termination for PID %s\n", pid);
                                }
                            } else {
                                printf("OYDVAT LOG: PID unknown, cannot terminate process.\n");
                            }
                            break;
                        }
                    }
                }
                if (!threat_found) {
                    printf("No threat detected in this process.\n");
                }
            }
        }
        free(name); free(pid); free(cmdline);
    }

    _pclose(pipe);

    if (!any_browser_found) {
        printf("Browser not open or not detected.\n");
    }
}

int main(void) {
    printf("Welcome to OYDVAT, or Official YouTube Dangerous Videos Abbreviation Tool\n");
    printf("This tool will help you protect against harmful videos that might sneak in YouTube\n\n");

    // Infinite loop similar to the Python script
    for (;;) {
        check_browser("msedge.exe");
        check_browser("yt-dlp.exe");
        check_browser("chrome.exe");
        check_browser("firefox.exe");
        check_browser("DuckDuckGo.exe");
        // No need for sleeping.
    }

    return 0;
}
