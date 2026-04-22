#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

typedef struct {
    int rid;
    char name[50];
    float latitude;
    float longitude;
    char cat_issue[50];
    int severity;
    time_t timestamp;
    char description[256];
} Report_t;

void init_district(const char *district_name) {
    mkdir(district_name, 0750);

    char path[512];
    int fd;

    snprintf(path, sizeof(path), "%s/reports.dat", district_name);
    fd = open(path, O_CREAT | O_RDWR, 0664);
    if (fd != -1) close(fd);

    snprintf(path, sizeof(path), "%s/district.cfg", district_name);
    fd = open(path, O_CREAT | O_RDWR, 0640);
    if (fd != -1) {
        write(fd, "2", 1);
        close(fd);
    }

    snprintf(path, sizeof(path), "%s/logged_district", district_name);
    fd = open(path, O_CREAT | O_RDWR, 0644);
    if (fd != -1) close(fd);
}

void create_district_symlink(const char *district_name) {
    char target[512];
    char link_name[512];

    snprintf(target, sizeof(target), "%s/reports.dat", district_name);
    snprintf(link_name, sizeof(link_name), "active_reports-%s", district_name);

    unlink(link_name);
    symlink(target, link_name);
}

int check_permission(const char *path, const char *role, mode_t required_bit) {
    struct stat st;
    if (stat(path, &st) == -1) return 0;
    if (strcmp(role, "manager") == 0) {
        return (st.st_mode & required_bit);
    } else if (strcmp(role, "inspector") == 0) {
        if (required_bit == S_IRUSR) return (st.st_mode & S_IRGRP);
        if (required_bit == S_IWUSR) return (st.st_mode & S_IWGRP);
        if (required_bit == S_IXUSR) return (st.st_mode & S_IXGRP);
    }
    return 0;
}

void log_action(const char *district, const char *user, const char *role, const char *action) {
    char path[512];
    snprintf(path, sizeof(path), "%s/logged_district", district);
    int fd = open(path, O_WRONLY | O_APPEND);
    if (fd != -1) {
        char buf[1024];
        int len = snprintf(buf, sizeof(buf), "%ld %s %s %s\n", time(NULL), user, role, action);
        write(fd, buf, len);
        close(fd);
    }
}


// AI parse and match functions

int parse_condition(const char *input, char *field, char *op, char *value) {
    if (input == NULL || field == NULL || op == NULL || value == NULL) {
        return 0;
    }

    char temp[256];
    strncpy(temp, input, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';

    char *token;

    token = strtok(temp, ":");
    if (token == NULL) return 0;
    strcpy(field, token);

    token = strtok(NULL, ":");
    if (token == NULL) return 0;
    strcpy(op, token);

    token = strtok(NULL, ":");
    if (token == NULL) return 0;
    strcpy(value, token);

    return 1;
}


int match_condition(Report_t *r, const char *field, const char *op, const char *value) {
    if (r == NULL || field == NULL || op == NULL || value == NULL) return 0;

    // --- Tratare campuri de tip NUMERIC (severity, rid, timestamp) ---
    if (strcmp(field, "severity") == 0 || strcmp(field, "rid") == 0 || strcmp(field, "timestamp") == 0) {
        long r_val;
        
        // Extragerea valorii corecte din structura in functie de campul cerut
        if (strcmp(field, "severity") == 0) {
            r_val = r->severity;
        } else if (strcmp(field, "rid") == 0) {
            r_val = r->rid;
        } else {
            // timestamp este de tip time_t, il tratam ca long pentru comparatie
            r_val = (long)r->timestamp;
        }

        // Convertim valoarea text din conditie intr-un numar lung
        long val_to_compare = atol(value);

        // Compararea matematica bazata pe operatorul primit
        if (strcmp(op, "==") == 0) return r_val == val_to_compare;
        if (strcmp(op, "!=") == 0) return r_val != val_to_compare;
        if (strcmp(op, "<") == 0)  return r_val < val_to_compare;
        if (strcmp(op, "<=") == 0) return r_val <= val_to_compare;
        if (strcmp(op, ">") == 0)  return r_val > val_to_compare;
        if (strcmp(op, ">=") == 0) return r_val >= val_to_compare;
    }

    // --- Tratare campuri de tip STRING (category, inspector) ---
    else if (strcmp(field, "category") == 0 || strcmp(field, "inspector") == 0) {
        char *r_str;
        
        // Maparea campurilor din cerinta la membrii structurii tale Report_t
        if (strcmp(field, "category") == 0) {
            r_str = r->cat_issue;
        } else {
            r_str = r->name; // campul 'inspector' corespunde numelui in structura ta
        }

        // Compararea lexicografica (alfabetica) folosind strcmp
        if (strcmp(op, "==") == 0) return strcmp(r_str, value) == 0;
        if (strcmp(op, "!=") == 0) return strcmp(r_str, value) != 0;
        if (strcmp(op, "<") == 0)  return strcmp(r_str, value) < 0;
        if (strcmp(op, "<=") == 0) return strcmp(r_str, value) <= 0;
        if (strcmp(op, ">") == 0)  return strcmp(r_str, value) > 0;
        if (strcmp(op, ">=") == 0) return strcmp(r_str, value) >= 0;
    }

    // Daca field-ul nu este recunoscut, conditia nu este indeplinita
    return 0; 
}




int main(int argc, char *argv[]) {
    if (argc < 2) return 1;

    char *role = NULL, *user = NULL, *command = NULL, *district = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) {
            role = argv[++i];
        } else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) {
            user = argv[++i];
        } else {
            if (command == NULL) command = argv[i];
            else if (district == NULL) district = argv[i];
        }
    }

    if (!role || !user || !command || !district) {
        printf("Utilizare: %s --role <r> --user <u> <comanda> <district>\n", argv[0]);
        return 1;
    }

    init_district(district);
    create_district_symlink(district);

    if (strcmp(command, "add") == 0) {
        char report_path[512];
        snprintf(report_path, sizeof(report_path), "%s/reports.dat", district);

        if (!check_permission(report_path, role, S_IWUSR)) {
            printf("Eroare: Rolul %s nu are drept de scriere pe %s\n", role, report_path);
            return 1;
        }

        log_action(district, user, role, command);
        printf("Acces permis. Gata de adaugat raport in %s\n", district);
    }

    return 0;
}
