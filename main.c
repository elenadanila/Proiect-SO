#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <signal.h>
#include <sys/wait.h>

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
    chmod(district_name, 0750);

    char path[512];
    int fd;

    snprintf(path, sizeof(path), "%s/reports.dat", district_name);
    fd = open(path, O_CREAT | O_RDWR, 0664);
    if (fd != -1) {
        chmod(path, 0664);
        close(fd);
    }

    snprintf(path, sizeof(path), "%s/district.cfg", district_name);
    fd = open(path, O_CREAT | O_RDWR, 0640);
    if (fd != -1) {
        chmod(path, 0640);
        write(fd, "2", 1);
        close(fd);
    }

    snprintf(path, sizeof(path), "%s/logged_district", district_name);
    fd = open(path, O_CREAT | O_RDWR, 0644);
    if (fd != -1) {
        chmod(path, 0644);
        close(fd);
    }
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
  if (strcmp(role, "manager") != 0) {
        return;
  }
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

void mode_to_string(mode_t mode, char *str) {
    str[0] = (mode & S_IRUSR) ? 'r' : '-';
    str[1] = (mode & S_IWUSR) ? 'w' : '-';
    str[2] = (mode & S_IXUSR) ? 'x' : '-';
    str[3] = (mode & S_IRGRP) ? 'r' : '-';
    str[4] = (mode & S_IWGRP) ? 'w' : '-';
    str[5] = (mode & S_IXGRP) ? 'x' : '-';
    str[6] = (mode & S_IROTH) ? 'r' : '-';
    str[7] = (mode & S_IWOTH) ? 'w' : '-';
    str[8] = (mode & S_IXOTH) ? 'x' : '-';
    str[9] = '\0';
}


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

int add_report_to_file(const char *district, Report_t *report) {
    char path[512];
    snprintf(path, sizeof(path), "%s/reports.dat", district);

    int fd = open(path, O_WRONLY | O_APPEND);

    if (fd == -1) {
        return -1;
    }

    ssize_t written = write(fd, report, sizeof(Report_t));
    if (written < 0) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

void display_reports(const char *district) {
    char path[512];
    snprintf(path, sizeof(path), "%s/reports.dat", district);

    int fd = open(path, O_RDONLY);
    if (fd == -1) return;

    Report_t r;
    while (read(fd, &r, sizeof(Report_t)) > 0) {
        printf("ID: %d | Inspector: %s | Cat: %s | Sev: %d | Time: %ld\n",
               r.rid, r.name, r.cat_issue, r.severity, (long)r.timestamp);
        printf("Coords: %.2f, %.2f | Desc: %s\n", r.latitude, r.longitude, r.description);
        printf("------------------------------------------\n");
    }

    close(fd);
}

int remove_report_from_file(const char *district, int target_id) {
    char path[512];
    snprintf(path, sizeof(path), "%s/reports.dat", district);

    int fd = open(path, O_RDWR);
    if (fd == -1) return -1;

    Report_t r;
    off_t pos = 0;
    int found = 0;

    while (read(fd, &r, sizeof(Report_t)) > 0) {
        if (r.rid == target_id) {
            found = 1;
            break;
        }
        pos += sizeof(Report_t);
    }

    if (found) {
        Report_t next_r;
        off_t current_pos = pos;
        while (read(fd, &next_r, sizeof(Report_t)) > 0) {
            off_t next_read_pos = lseek(fd, 0, SEEK_CUR);
            lseek(fd, current_pos, SEEK_SET);
            write(fd, &next_r, sizeof(Report_t));
            current_pos += sizeof(Report_t);
            lseek(fd, next_read_pos, SEEK_SET);
        }
        struct stat st;
        fstat(fd, &st);
        ftruncate(fd, st.st_size - sizeof(Report_t));
    }

    close(fd);
    return found ? 0 : -1;
}

int update_threshold_file(const char *district, const char *new_value) {
    char path[512];
    snprintf(path, sizeof(path), "%s/district.cfg", district);

    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd == -1) return -1;

    write(fd, new_value, strlen(new_value));
    close(fd);
    return 0;
}


int match_condition(Report_t *r, const char *field, const char *op, const char *value) {
    if (r == NULL || field == NULL || op == NULL || value == NULL) return 0;

    if (strcmp(field, "severity") == 0 || strcmp(field, "rid") == 0 || strcmp(field, "timestamp") == 0) {
        long r_val;

        if (strcmp(field, "severity") == 0) {
            r_val = r->severity;
        } else if (strcmp(field, "rid") == 0) {
            r_val = r->rid;
        } else {
            r_val = (long)r->timestamp;
        }

        long val_to_compare = atol(value);

        if (strcmp(op, "==") == 0) return r_val == val_to_compare;
        if (strcmp(op, "!=") == 0) return r_val != val_to_compare;
        if (strcmp(op, "<") == 0)  return r_val < val_to_compare;
        if (strcmp(op, "<=") == 0) return r_val <= val_to_compare;
        if (strcmp(op, ">") == 0)  return r_val > val_to_compare;
        if (strcmp(op, ">=") == 0) return r_val >= val_to_compare;
    }

    else if (strcmp(field, "category") == 0 || strcmp(field, "inspector") == 0) {
        char *r_str;

        if (strcmp(field, "category") == 0) {
            r_str = r->cat_issue;
        } else {
            r_str = r->name;
        }

        if (strcmp(op, "==") == 0) return strcmp(r_str, value) == 0;
        if (strcmp(op, "!=") == 0) return strcmp(r_str, value) != 0;
        if (strcmp(op, "<") == 0)  return strcmp(r_str, value) < 0;
        if (strcmp(op, "<=") == 0) return strcmp(r_str, value) <= 0;
        if (strcmp(op, ">") == 0)  return strcmp(r_str, value) > 0;
        if (strcmp(op, ">=") == 0) return strcmp(r_str, value) >= 0;
    }

    return 0;
}

void filter_reports(const char *district, int cond_count, char **cond_args) {
    char path[512];
    snprintf(path, sizeof(path), "%s/reports.dat", district);

    int fd = open(path, O_RDONLY);
    if (fd == -1) return;

    Report_t r;
    while (read(fd, &r, sizeof(Report_t)) > 0) {
        int all_match = 1;

        for (int i = 0; i < cond_count; i++) {
            char field[50], op[10], value[100];
            if (parse_condition(cond_args[i], field, op, value)) {
                if (!match_condition(&r, field, op, value)) {
                    all_match = 0;
                    break;
                }
            }
        }

        if (all_match) {
            printf("MATCH - ID: %d | Cat: %s | Sev: %d | Desc: %s\n",
                   r.rid, r.cat_issue, r.severity, r.description);
        }
    }

    close(fd);
}

int get_next_id(const char *district) {
    struct stat st;
    char path[512];
    snprintf(path, sizeof(path), "%s/reports.dat", district);

    if (stat(path, &st) == -1) return 1;
    return (st.st_size / sizeof(Report_t)) + 1;
}


void view_report(const char *district, int target_id, const char *role) {
    char path[512];
    snprintf(path, sizeof(path), "%s/reports.dat", district);

    if (!check_permission(path, role, S_IRUSR)) {
        printf("Eroare: Rolul %s nu are drept de citire pe %s\n", role, path);
        return;
    }

    int fd = open(path, O_RDONLY);
    if (fd == -1) return;

    Report_t r;
    int found = 0;
    while (read(fd, &r, sizeof(Report_t)) > 0) {
        if (r.rid == target_id) {
            printf("--- Detalii Raport ID: %d ---\n", r.rid);
            printf("Inspector: %s\n", r.name);
            printf("Coordonate: %.4f, %.4f\n", r.latitude, r.longitude);
            printf("Categorie: %s\n", r.cat_issue);
            printf("Severitate: %d\n", r.severity);
            printf("Data: %s", ctime(&r.timestamp));
            printf("Descriere: %s\n", r.description);
            printf("---------------------------\n");
            found = 1;
            break;
        }
    }

    if (!found) printf("Raportul cu ID-ul %d nu a fost gasit.\n", target_id);
    close(fd);
}


void check_dangling_links() {
    DIR *dir = opendir(".");
    if (dir == NULL) return;

    struct dirent *entry;
    struct stat lst;
    struct stat st;

    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "active_reports-", 15) == 0) {
            if (lstat(entry->d_name, &lst) == 0) {
                if (S_ISLNK(lst.st_mode)) {
                    if (stat(entry->d_name, &st) == -1) {
                        printf("AVERTISMENT: Legatura simbolica dangling detectata: %s\n", entry->d_name);
                    }
                }
            }
        }
    }
    closedir(dir);
}





int main(int argc, char *argv[]) {
    char *role = NULL, *user = NULL, *command = NULL, *district = NULL;
    int cmd_idx = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--role") == 0 && i + 1 < argc) role = argv[++i];
        else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) user = argv[++i];
        else if (command == NULL) { command = argv[i]; cmd_idx = i; }
        else if (district == NULL) district = argv[i];
    }

    if (!role || !user || !command || !district) {
        printf("Utilizare: %s --role <r> --user <u> <comanda> <district> [optiuni]\n", argv[0]);
        return 1;
    }

    if (strcmp(command, "remove_district") == 0) {
        if (strcmp(role, "manager") != 0) {
            printf("EROARE! Doar managerul poate sterge districte\n");
            return 1;
        }

        pid_t pid = fork();

        if (pid == 0) {
            execlp("rm", "rm", "-rf", district, NULL);
            exit(1);
        }else if (pid > 0){
            wait(NULL);
            char link_name[512];
            snprintf(link_name, sizeof(link_name), "active_reports-%s", district);
            unlink(link_name);

            printf("Distictul %s a fost sters cu succes!\n", district);
            return 0;
        }
    }

    init_district(district);
    create_district_symlink(district);
    check_dangling_links();

    if (strcmp(command, "add") == 0) {
        char report_path[512];
        snprintf(report_path, sizeof(report_path), "%s/reports.dat", district);

        if (!check_permission(report_path, role, S_IWUSR)) {
            printf("Eroare: Rolul %s nu are drept de scriere pe %s\n", role, report_path);
            return 1;
        }

        Report_t r;
        r.rid = get_next_id(district);
        strncpy(r.name, user, 49);
        printf("Latitudine: "); scanf("%f", &r.latitude);
        printf("Longitudine: "); scanf("%f", &r.longitude);
        printf("Categorie: "); scanf("%s", r.cat_issue);
        printf("Severitate (1-3): "); scanf("%d", &r.severity);
        printf("Descriere: "); getchar(); fgets(r.description, 255, stdin);
        r.description[strcspn(r.description, "\n")] = 0;
        r.timestamp = time(NULL);

        if (add_report_to_file(district, &r) == 0) {
            log_action(district, user, role, command);
            printf("Raport adaugat cu succes (ID: %d).\n", r.rid);
        }
    }
    else if (strcmp(command, "list") == 0) {
        struct stat st;
        char path[512];
        snprintf(path, sizeof(path), "%s/reports.dat", district);

        if (stat(path, &st) == 0) {
            if (!check_permission(path, role, S_IRUSR)) {
                printf("Eroare: Rolul %s nu are drept de citire pe %s\n", role, path);
                return 1;
            }

            char perm_str[11];
            mode_to_string(st.st_mode, perm_str);
            printf("Fisier: %s\n", path);
            printf("Permisiuni: %s\n", perm_str);
            printf("Dimensiune: %ld bytes\n", (long)st.st_size);
            printf("Ultima modificare: %s", ctime(&st.st_mtime));
        }
        display_reports(district);
        log_action(district, user, role, command);
    }
    else if (strcmp(command, "view") == 0) {
        if (argc < cmd_idx + 3) {
            printf("Utilizare: view <district> <report_id>\n");
            return 1;
        }
        int target_id = atoi(argv[cmd_idx + 2]);
        view_report(district, target_id, role);
        log_action(district, user, role, command);
    }
    else if (strcmp(command, "remove_report") == 0) {
        char report_path[512];
        snprintf(report_path, sizeof(report_path), "%s/reports.dat", district);

        if (strcmp(role, "manager") != 0) {
            printf("Eroare: Doar managerul are dreptul de a sterge rapoarte.\n");
            return 1;
        }

        int id_to_remove = atoi(argv[cmd_idx + 2]);
        if (remove_report_from_file(district, id_to_remove) == 0) {
            log_action(district, user, role, command);
            printf("Raportul %d a fost sters.\n", id_to_remove);
        } else {
            printf("Raportul nu a fost gasit.\n");
        }
    }
    else if (strcmp(command, "update_threshold") == 0) {
        char cfg_path[512];
        snprintf(cfg_path, sizeof(cfg_path), "%s/district.cfg", district);

        struct stat st;
        if (stat(cfg_path, &st) == -1) return 1;

        if (!((st.st_mode & S_IRUSR) && (st.st_mode & S_IWUSR) && (st.st_mode & S_IRGRP))) {
            printf("Eroare: Permisiunile district.cfg nu sunt corecte (trebuie sa fie 640).\n");
            return 1;
        }

        if (strcmp(role, "manager") != 0) {
            printf("Acces interzis: Doar managerul poate modifica pragul.\n");
            return 1;
        }

        if (update_threshold_file(district, argv[cmd_idx + 2]) == 0) {
            log_action(district, user, role, command);
            printf("Prag actualizat la %s.\n", argv[cmd_idx + 2]);
        }
    }
    else if (strcmp(command, "filter") == 0) {
        int cond_count = argc - (cmd_idx + 2);
        if (cond_count > 0) {
            filter_reports(district, cond_count, &argv[cmd_idx + 2]);
            log_action(district, user, role, command);
        } else {
            printf("Specificati conditii (ex: severity:>:5).\n");
        }
    }


    return 0;
}