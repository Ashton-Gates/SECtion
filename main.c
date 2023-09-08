#include <stdio.h>
#include "web.h"
#include "proxy.h"

int main() {
    int choice;
    char target[100];

    do {
        printf(
        " _____  _____    _____   _    _            \n"
       "/  ___||  ___|  /  __  \| |   (_)            \n"
       "\\ `--. | |__   | /   \/| |_   _    ___   _ __ \n"
       " `--. \\|  __|  | |     |  __|| |  / _ \ | '_ \ \n"
       "/\\__/ /| |___  | \\__/\| |_  | | | (_) || | | | \n"
       "\\____/ \\____/  \\____/ \__| |_|  \___/ |_| |_|  \n"
       "                                           \n"
       "                                           \n");

        printf("Select an option:\n");
        printf("1. Scan a web server\n");
        printf("2. Scan a proxy server\n");
        printf("3. Cancel\n");
        scanf("%d", &choice);

        switch(choice) {
            case 1:
                printf("Enter the web server URL or IP: ");
                scanf("%s", target);
                web_scan(target);
                break;
            case 2:
                printf("Enter the proxy server URL or IP: ");
                scanf("%s", target);
                proxy_scan(target);
                break;
            case 3:
                printf("Exiting...\n");
                break;
            default:
                printf("Invalid choice. Please select a valid option.\n");
                break;
        }
    } while(choice != 3);

    return 0;
}
