#define _GNU_SOURCE

#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

#include "flags.h"

#ifndef SQLLAB_DEFENSE_SOURCE
#define SQLLAB_DEFENSE_SOURCE "/home/seed/lab/defense/unsafe.php"
#endif

#define SQLLAB_BASE_URL "http://127.0.0.1"
#define SQLLAB_HOST_HEADER "Host: www.seed-server.com"
#define SQLLAB_MAX_RESPONSE (2u * 1024u * 1024u)
#define SQLLAB_MAX_SOURCE (1024u * 1024u)
#define SQLLAB_MAX_FLAG 128u

struct http_response {
    char *data;
    size_t length;
};

static const unsigned char *const FLAG_DATA[4] = {
    SQLLAB_FLAG_1,
    SQLLAB_FLAG_2,
    SQLLAB_FLAG_3,
    SQLLAB_FLAG_4,
};

static const size_t FLAG_LENGTHS[4] = {
    SQLLAB_FLAG_1_LEN,
    SQLLAB_FLAG_2_LEN,
    SQLLAB_FLAG_3_LEN,
    SQLLAB_FLAG_4_LEN,
};

static const unsigned int FLAG_OFFSETS[4] = {
    SQLLAB_FLAG_1_OFFSET,
    SQLLAB_FLAG_2_OFFSET,
    SQLLAB_FLAG_3_OFFSET,
    SQLLAB_FLAG_4_OFFSET,
};

static void secure_zero(void *buffer, size_t length)
{
    volatile unsigned char *cursor = buffer;
    while (length > 0u) {
        *cursor++ = 0u;
        length--;
    }
}

static bool harden_process(void)
{
    const struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core) != 0) {
        return false;
    }
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        return false;
    }
#ifdef PR_SET_PTRACER
    if (prctl(PR_SET_PTRACER, 0, 0, 0, 0) != 0) {
        return false;
    }
#endif
    return true;
}

static bool enter_restricted_runtime(void)
{
    const uid_t real_uid = getuid();
    const gid_t real_gid = getgid();

    /*
     * Student checks must enter through a root-owned set-user-ID executable.
     * The kernel then starts the dynamic loader in secure mode, which ignores
     * LD_PRELOAD/LD_LIBRARY_PATH before any user-controlled constructor can
     * run.  Drop every elevated identity before parsing input or using curl.
     */
    if (real_uid != 0) {
        if (geteuid() != 0 || getauxval(AT_SECURE) == 0u) {
            return false;
        }
    }
    if (clearenv() != 0) {
        return false;
    }
    if (real_uid != 0) {
        if (setgroups(0u, NULL) != 0
            || setresgid(real_gid, real_gid, real_gid) != 0
            || setresuid(real_uid, real_uid, real_uid) != 0
            || geteuid() != real_uid
            || getegid() != real_gid) {
            return false;
        }
    }
    return harden_process();
}

static bool decode_flag(size_t index, unsigned char *output, size_t capacity)
{
    size_t position;
    size_t length;
    unsigned int offset;

    if (index >= 4u) {
        return false;
    }
    length = FLAG_LENGTHS[index];
    offset = FLAG_OFFSETS[index];
    if (length > SQLLAB_MAX_FLAG || capacity <= length) {
        return false;
    }
    for (position = 0u; position < length; position++) {
        const unsigned int mix = (0xA5u + (unsigned int)position * 29u + offset * 17u) & 0xFFu;
        output[position] = FLAG_DATA[index][position]
            ^ SQLLAB_MASK_KEY[(position + (size_t)offset) % sizeof(SQLLAB_MASK_KEY)]
            ^ (unsigned char)mix;
    }
    output[length] = '\0';
    return true;
}

static bool print_flag(size_t index)
{
    unsigned char flag[SQLLAB_MAX_FLAG + 1u];
    bool success = false;

    if (decode_flag(index, flag, sizeof(flag))) {
        printf("Flag de la tache %zu : %s\n", index + 1u, (const char *)flag);
        success = true;
    }
    secure_zero(flag, sizeof(flag));
    return success;
}

static int selftest(void)
{
    size_t index;
    if (geteuid() != 0) {
        fputs("Auto-test reserve a root.\n", stderr);
        return 1;
    }
    for (index = 0u; index < 4u; index++) {
        unsigned char flag[SQLLAB_MAX_FLAG + 1u];
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digest_length = 0u;
        size_t byte_index;

        if (!decode_flag(index, flag, sizeof(flag))
            || EVP_Digest(flag, FLAG_LENGTHS[index], digest, &digest_length, EVP_sha256(), NULL) != 1
            || digest_length != 32u) {
            secure_zero(flag, sizeof(flag));
            secure_zero(digest, sizeof(digest));
            return 1;
        }
        for (byte_index = 0u; byte_index < digest_length; byte_index++) {
            printf("%02x", digest[byte_index]);
        }
        putchar('\n');
        secure_zero(flag, sizeof(flag));
        secure_zero(digest, sizeof(digest));
    }
    return 0;
}

static size_t receive_http_data(void *contents, size_t size, size_t count, void *context)
{
    struct http_response *response = context;
    size_t bytes;
    char *expanded;

    if (size != 0u && count > SIZE_MAX / size) {
        return 0u;
    }
    bytes = size * count;
    if (bytes > SQLLAB_MAX_RESPONSE || response->length > SQLLAB_MAX_RESPONSE - bytes) {
        return 0u;
    }
    expanded = realloc(response->data, response->length + bytes + 1u);
    if (expanded == NULL) {
        return 0u;
    }
    response->data = expanded;
    memcpy(response->data + response->length, contents, bytes);
    response->length += bytes;
    response->data[response->length] = '\0';
    return bytes;
}

static void free_response(struct http_response *response)
{
    free(response->data);
    response->data = NULL;
    response->length = 0u;
}

static bool http_get(const char *path, struct http_response *response)
{
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    CURLcode result;
    long status = 0;
    char url[2048];
    int written;
    bool success = false;

    response->data = NULL;
    response->length = 0u;
    written = snprintf(url, sizeof(url), "%s%s", SQLLAB_BASE_URL, path);
    if (written < 0 || (size_t)written >= sizeof(url)) {
        return false;
    }
    curl = curl_easy_init();
    if (curl == NULL) {
        return false;
    }
    headers = curl_slist_append(headers, SQLLAB_HOST_HEADER);
    if (headers == NULL) {
        curl_easy_cleanup(curl);
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_http_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "SEED-SQLi-checker/1.0");

    result = curl_easy_perform(curl);
    if (result == CURLE_OK
        && curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK
        && status >= 200L && status < 300L && response->data != NULL) {
        success = true;
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (!success) {
        free_response(response);
    }
    return success;
}

static const char *find_case_insensitive(const char *haystack, const char *needle)
{
    size_t needle_length;
    const char *candidate;

    if (haystack == NULL || needle == NULL) {
        return NULL;
    }
    needle_length = strlen(needle);
    if (needle_length == 0u) {
        return haystack;
    }
    for (candidate = haystack; *candidate != '\0'; candidate++) {
        size_t index;
        for (index = 0u; index < needle_length; index++) {
            if (candidate[index] == '\0'
                || tolower((unsigned char)candidate[index]) != tolower((unsigned char)needle[index])) {
                break;
            }
        }
        if (index == needle_length) {
            return candidate;
        }
    }
    return NULL;
}

static bool contains_case_insensitive(const char *haystack, const char *needle)
{
    return find_case_insensitive(haystack, needle) != NULL;
}

static bool copy_trimmed(const char *start, const char *end, char *output, size_t capacity)
{
    size_t length;
    while (start < end && isspace((unsigned char)*start)) {
        start++;
    }
    while (end > start && isspace((unsigned char)end[-1])) {
        end--;
    }
    length = (size_t)(end - start);
    if (length == 0u || length >= capacity) {
        return false;
    }
    memcpy(output, start, length);
    output[length] = '\0';
    return true;
}

static bool extract_employee_cells(
    const char *html,
    const char *employee,
    char values[][128],
    size_t value_count)
{
    const char *name = html;

    while ((name = find_case_insensitive(name, employee)) != NULL) {
        const char *heading_end = find_case_insensitive(name, "</th>");
        const char *cursor;
        size_t index;
        if (heading_end == NULL || (size_t)(heading_end - name) > 96u) {
            name++;
            continue;
        }
        cursor = heading_end + 5;
        for (index = 0u; index < value_count; index++) {
            const char *cell = find_case_insensitive(cursor, "<td");
            const char *content;
            const char *end;
            if (cell == NULL) {
                break;
            }
            content = strchr(cell, '>');
            if (content == NULL) {
                break;
            }
            content++;
            end = find_case_insensitive(content, "</td>");
            if (end == NULL || !copy_trimmed(content, end, values[index], 128u)) {
                break;
            }
            cursor = end + 5;
        }
        if (index == value_count) {
            return true;
        }
        name++;
    }
    return false;
}

static bool is_admin_roster(const char *html)
{
    return contains_case_insensitive(html, "User Details")
        && contains_case_insensitive(html, "Alice")
        && contains_case_insensitive(html, "Boby")
        && contains_case_insensitive(html, "Admin")
        && contains_case_insensitive(html, "99999");
}

static bool read_answer(const char *prompt, char *answer, size_t capacity)
{
    size_t length;
    int character;
    char *start;

    fputs(prompt, stdout);
    fflush(stdout);
    if (fgets(answer, (int)capacity, stdin) == NULL) {
        return false;
    }
    length = strlen(answer);
    if (length > 0u && answer[length - 1u] != '\n' && !feof(stdin)) {
        while ((character = getchar()) != '\n' && character != EOF) {
        }
        return false;
    }
    while (length > 0u && isspace((unsigned char)answer[length - 1u])) {
        answer[--length] = '\0';
    }
    start = answer;
    while (*start != '\0' && isspace((unsigned char)*start)) {
        start++;
    }
    if (start != answer) {
        memmove(answer, start, strlen(start) + 1u);
    }
    return answer[0] != '\0';
}

static bool valid_encoded_component(const char *value)
{
    size_t index;
    bool has_escape = false;
    for (index = 0u; value[index] != '\0'; index++) {
        const unsigned char character = (unsigned char)value[index];
        if (isalnum(character) || character == '-' || character == '_' || character == '.' || character == '~') {
            continue;
        }
        if (character == '%' && value[index + 1u] != '\0' && value[index + 2u] != '\0'
            && isxdigit((unsigned char)value[index + 1u])
            && isxdigit((unsigned char)value[index + 2u])) {
            has_escape = true;
            index += 2u;
            continue;
        }
        return false;
    }
    return has_escape;
}

static char *percent_encode(const char *value)
{
    static const char HEX[] = "0123456789ABCDEF";
    const size_t length = strlen(value);
    char *encoded;
    size_t input_index;
    size_t output_index = 0u;

    if (length > (SIZE_MAX - 1u) / 3u) {
        return NULL;
    }
    encoded = malloc(length * 3u + 1u);
    if (encoded == NULL) {
        return NULL;
    }
    for (input_index = 0u; input_index < length; input_index++) {
        const unsigned char character = (unsigned char)value[input_index];
        if (isalnum(character) || character == '-' || character == '_' || character == '.' || character == '~') {
            encoded[output_index++] = (char)character;
        } else {
            encoded[output_index++] = '%';
            encoded[output_index++] = HEX[character >> 4u];
            encoded[output_index++] = HEX[character & 0x0Fu];
        }
    }
    encoded[output_index] = '\0';
    return encoded;
}

static bool parse_salary(const char *value, long *salary)
{
    char *end = NULL;
    long parsed;
    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed < 0L) {
        return false;
    }
    *salary = parsed;
    return true;
}

static bool fetch_admin_page(struct http_response *response)
{
    return http_get("/unsafe_home.php?username=Admin%27%20%23&Password=x", response)
        && is_admin_roster(response->data);
}

static bool run_check_1(void)
{
    struct http_response response = {0};
    char cells[4][128];
    char eid[128];
    char salary[128];
    char ssn[128];
    bool success = false;

    if (!fetch_admin_page(&response) || !extract_employee_cells(response.data, "Alice", cells, 4u)) {
        fputs("Application ou base SQL indisponible.\n", stderr);
        goto cleanup;
    }
    if (!read_answer("EID d'Alice : ", eid, sizeof(eid))
        || !read_answer("Salaire actuel d'Alice : ", salary, sizeof(salary))
        || !read_answer("SSN d'Alice : ", ssn, sizeof(ssn))) {
        fputs("Reponse invalide.\n", stderr);
        goto cleanup;
    }
    if (strcmp(eid, cells[0]) != 0 || strcmp(salary, cells[1]) != 0 || strcmp(ssn, cells[3]) != 0) {
        fputs("Les trois valeurs ne correspondent pas a la base.\n", stderr);
        goto cleanup;
    }
    success = print_flag(0u);

cleanup:
    free_response(&response);
    return success;
}

static bool run_check_2(void)
{
    struct http_response response = {0};
    char payload[512];
    char path[1024];
    int written;
    bool success = false;

    if (!read_answer("Payload username URL-encode : ", payload, sizeof(payload))
        || !valid_encoded_component(payload)) {
        fputs("Le payload doit etre un composant URL encode (par exemple %27).\n", stderr);
        return false;
    }
    written = snprintf(path, sizeof(path), "/unsafe_home.php?username=%s&Password=x", payload);
    if (written < 0 || (size_t)written >= sizeof(path)) {
        return false;
    }
    if (!http_get(path, &response) || !is_admin_roster(response.data)) {
        fputs("Ce payload n'ouvre pas la page administrateur.\n", stderr);
        goto cleanup;
    }
    success = print_flag(1u);

cleanup:
    free_response(&response);
    return success;
}

static bool run_check_3(void)
{
    struct http_response admin = {0};
    struct http_response login = {0};
    char alice[2][128];
    char boby[2][128];
    char password[256];
    char path[1024];
    char *encoded_password = NULL;
    long alice_salary;
    long boby_salary;
    int written;
    bool success = false;

    if (!fetch_admin_page(&admin)
        || !extract_employee_cells(admin.data, "Alice", alice, 2u)
        || !extract_employee_cells(admin.data, "Boby", boby, 2u)
        || !parse_salary(alice[1], &alice_salary)
        || !parse_salary(boby[1], &boby_salary)) {
        fputs("Impossible de verifier les salaires via la page administrateur.\n", stderr);
        goto cleanup;
    }
    if (alice_salary <= 20000L || boby_salary != 1L) {
        fputs("Les salaires attendus (Alice > 20000, Boby = 1) ne sont pas en base.\n", stderr);
        goto cleanup;
    }
    if (!read_answer("Nouveau mot de passe en clair de Boby : ", password, sizeof(password))) {
        fputs("Mot de passe invalide.\n", stderr);
        goto cleanup;
    }
    if (strcmp(password, "seedboby") == 0) {
        fputs("Le mot de passe de Boby est encore sa valeur initiale.\n", stderr);
        goto cleanup;
    }
    encoded_password = percent_encode(password);
    secure_zero(password, sizeof(password));
    if (encoded_password == NULL) {
        goto cleanup;
    }
    written = snprintf(
        path,
        sizeof(path),
        "/unsafe_home.php?username=Boby&Password=%s",
        encoded_password);
    secure_zero(encoded_password, strlen(encoded_password));
    free(encoded_password);
    encoded_password = NULL;
    if (written < 0 || (size_t)written >= sizeof(path)
        || !http_get(path, &login)
        || !contains_case_insensitive(login.data, "Boby Profile")) {
        fputs("La connexion a Boby avec ce mot de passe a echoue.\n", stderr);
        goto cleanup;
    }
    success = print_flag(2u);

cleanup:
    if (encoded_password != NULL) {
        secure_zero(encoded_password, strlen(encoded_password));
        free(encoded_password);
    }
    secure_zero(password, sizeof(password));
    free_response(&admin);
    free_response(&login);
    return success;
}

static char *read_source_file(const char *path)
{
    FILE *stream = fopen(path, "rb");
    long size;
    char *contents;
    size_t read_count;

    if (stream == NULL || fseek(stream, 0L, SEEK_END) != 0) {
        if (stream != NULL) {
            fclose(stream);
        }
        return NULL;
    }
    size = ftell(stream);
    if (size < 0L || (unsigned long)size > SQLLAB_MAX_SOURCE || fseek(stream, 0L, SEEK_SET) != 0) {
        fclose(stream);
        return NULL;
    }
    contents = malloc((size_t)size + 1u);
    if (contents == NULL) {
        fclose(stream);
        return NULL;
    }
    read_count = fread(contents, 1u, (size_t)size, stream);
    if (read_count != (size_t)size || ferror(stream)) {
        free(contents);
        fclose(stream);
        return NULL;
    }
    contents[read_count] = '\0';
    fclose(stream);
    return contents;
}

static void strip_php_comments(char *source)
{
    enum comment_state {
        CODE,
        SINGLE_QUOTE,
        DOUBLE_QUOTE,
        LINE_COMMENT,
        BLOCK_COMMENT
    } state = CODE;
    size_t input = 0u;
    size_t output = 0u;
    bool escaped = false;

    while (source[input] != '\0') {
        const char current = source[input];
        const char next = source[input + 1u];
        if (state == CODE) {
            if (current == '/' && next == '/') {
                state = LINE_COMMENT;
                input += 2u;
                continue;
            }
            if (current == '/' && next == '*') {
                state = BLOCK_COMMENT;
                input += 2u;
                continue;
            }
            if (current == '#') {
                state = LINE_COMMENT;
                input++;
                continue;
            }
            if (current == '\'') {
                state = SINGLE_QUOTE;
                escaped = false;
            } else if (current == '"') {
                state = DOUBLE_QUOTE;
                escaped = false;
            }
            source[output++] = source[input++];
        } else if (state == SINGLE_QUOTE || state == DOUBLE_QUOTE) {
            /* Ignore tokens placed only inside PHP string literals. */
            source[output++] = current == '\n' ? '\n' : ' ';
            input++;
            if (escaped) {
                escaped = false;
            } else if (current == '\\') {
                escaped = true;
            } else if ((state == SINGLE_QUOTE && current == '\'')
                || (state == DOUBLE_QUOTE && current == '"')) {
                state = CODE;
            }
        } else if (state == LINE_COMMENT) {
            input++;
            if (current == '\n') {
                source[output++] = '\n';
                state = CODE;
            }
        } else {
            if (current == '*' && next == '/') {
                input += 2u;
                state = CODE;
            } else {
                if (current == '\n') {
                    source[output++] = '\n';
                }
                input++;
            }
        }
    }
    source[output] = '\0';
}

static bool source_uses_prepared_statement(void)
{
    char *source = read_source_file(SQLLAB_DEFENSE_SOURCE);
    bool valid;
    if (source == NULL) {
        return false;
    }
    strip_php_comments(source);
    valid = strstr(source, "->prepare") != NULL
        && strstr(source, "->bind_param") != NULL
        && strstr(source, "->execute") != NULL;
    secure_zero(source, strlen(source));
    free(source);
    return valid;
}

static bool run_check_4(void)
{
    struct http_response valid_login = {0};
    struct http_response injection = {0};
    bool success = false;

    if (!source_uses_prepared_statement()) {
        fputs("Le source defense/unsafe.php doit utiliser prepare, bind_param et execute.\n", stderr);
        return false;
    }
    if (!http_get("/defense/getinfo.php?username=Alice&Password=seedalice", &valid_login)
        || !contains_case_insensitive(valid_login.data, "<b>Alice</b>")
        || !contains_case_insensitive(valid_login.data, "10000")) {
        fputs("La requete preparee refuse une connexion Alice valide.\n", stderr);
        goto cleanup;
    }
    if (!http_get("/defense/getinfo.php?username=Admin%27%20%23&Password=x", &injection)) {
        fputs("La page de defense est indisponible.\n", stderr);
        goto cleanup;
    }
    if (contains_case_insensitive(injection.data, "<b>Admin</b>")
        || contains_case_insensitive(injection.data, "99999")
        || contains_case_insensitive(injection.data, "43254314")) {
        fputs("L'injection administrateur fonctionne encore sur la page de defense.\n", stderr);
        goto cleanup;
    }
    success = print_flag(3u);

cleanup:
    free_response(&valid_login);
    free_response(&injection);
    return success;
}

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s check <1|2|3|4>\n", program);
}

int main(int argc, char **argv)
{
    char *end = NULL;
    long check_number;
    bool success = false;

    if (!enter_restricted_runtime()) {
        fputs("Installation securisee du validateur absente ou invalide.\n", stderr);
        return 2;
    }
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0) {
        return selftest();
    }
    if (argc != 3 || strcmp(argv[1], "check") != 0) {
        usage(argv[0]);
        return 2;
    }
    errno = 0;
    check_number = strtol(argv[2], &end, 10);
    if (errno != 0 || end == argv[2] || *end != '\0' || check_number < 1L || check_number > 4L) {
        usage(argv[0]);
        return 2;
    }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        fputs("Initialisation HTTP impossible.\n", stderr);
        return 2;
    }
    switch (check_number) {
        case 1L:
            success = run_check_1();
            break;
        case 2L:
            success = run_check_2();
            break;
        case 3L:
            success = run_check_3();
            break;
        case 4L:
            success = run_check_4();
            break;
        default:
            break;
    }
    curl_global_cleanup();
    return success ? 0 : 1;
}
