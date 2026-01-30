/* File Descriptor Table Visualizer
   github.com/danielPrice01 26sp    */
// TODO add comments
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/************
 * MACROS
 ***********/

#define PIPE_READ "pipe_read"
#define PIPE_WRITE "pipe_write"
#define MAX_PROCESSES (4)
#define MAX_PIPES (4)
#define NUM_COLS (4)

/************
 * STRUCTS
 ***********/

typedef enum { REGULAR, PIPE, STD_STREAM } f_type;

typedef struct {
  uint8_t read_open;   // 0 if closed, otherwise number times open
  uint8_t write_open;  // 0 if closed, otherwise number times open
} pipe;

typedef struct {
  char* name;
  char flags[4];  // read, write, executable
                  // simplified from 10 flags in standard Unix
  f_type file_type;
  // this is acting like the pointer in the system wide file table to the actual
  // underlying object
  union {
    size_t offset;
    pipe* pipe;
    void* stream;  // pretending this is a stream*
  } u;
  uint8_t ref_count;  // mirrors unix ref count; for internal use regarding when
                      // to free
} fd_entry;

typedef enum { FD_MOD_FLAGS, FD_MOD_OFF } fd_mod_kind;

typedef struct {
  fd_mod_kind kind;
  union {
    size_t offset;
    char flags[4];
  } u;
} fd_mod;

// ownership: fd_table owns the files and is in charge of cleanup
typedef struct {
  fd_entry** files;  // the fd_entry* points to "System-Wide Open File Table"
  size_t num_files;
  size_t size;
} fd_table;

typedef struct {
  fd_table* table;
  pipe* process_pipes[MAX_PIPES];
  pid_t pid;
  pid_t ppid;  // parent pid, if NULL, parent is shell
} process;     // ownership: process owns table and pipe and is responsible for
               // cleanup

/************************
 * FD_ENTRY FUNCTIONS
 ***********************/

fd_entry* create_fd_entry(char* flags,
                          char* name,
                          f_type file_type,
                          pipe* pipe);
static inline fd_mod fd_mod_offset(size_t offset);
static inline fd_mod fd_mod_flags(char r, char w, char x);
int modify_fd_entry(fd_entry* entry, fd_mod m);
void delete_fd_entry(fd_entry* entry);
fd_table* create_fd_table(void);
int modify_fd_table(fd_table* table, size_t idx, fd_mod m);
void fd_table_resize(fd_table* table, size_t new_size);
int add_file_fd_table(fd_table* table, fd_entry* entry);
int close_file_fd_table(fd_table* table, size_t entry_idx);
fd_table* duplicate_fd_table(fd_table* table);
void delete_fd_table(fd_table* table);

/************************
 * PIPE FUNCTIONS
 ***********************/

pipe* create_pipe(void);
pipe* duplicate_pipe(pipe* input_pipe);
void add_pipe_to_process(process* input_process, pipe* input_pipe);
void delete_pipe(pipe* pipe);

/************************
 * PROCESS FUNCTIONS
 ***********************/

process* create_new_process(void);
process* create_child_process(process* input_p, pid_t pid);
void delete_process(process* p);

/************************
 * INLINE HELPERS
 ***********************/

static inline int pipe_idx_available(process* p);
static inline size_t max(size_t a, size_t b);
static inline int contains_char(char* string, char c);
static inline int buf_contains_prefix(char* buf, char* str);
static inline int str_equal(char* str1, char* str2);
static inline size_t digits(size_t x);

/************************
 * PRINTING FUNCTIONS
 ***********************/

void construct_row(size_t padding,
                   char* buf,
                   size_t buf_size,
                   char* delim,
                   char* col_vals[],
                   size_t desired_col_len[]);
void print_fd_table(fd_table* table);
void print_pipe(pipe* pipe);
void print_invalid_command_message(void);
void print_start_message(void);
void print_help_message(char* command);
void print_functions_list(void);

/************************
 * MAIN WRAPPER FUNCTIONS
 ***********************/

void handle_open(char* buf, fd_table* table);
void handle_close(char* buf, fd_table* table);
void handle_read(char* buf, fd_table* table);
void handle_write(char* buf, fd_table* table);
void handle_fseek(char* buf, fd_table* table);
void handle_pipe(process* p);
void handle_pipe_list(process* p);
void handle_process_switch(char* buf,
                           size_t* process_idx,
                           process* processes[]);
void handle_process_list(process* processes[]);
void handle_process_current(process* p);
void handle_process_parent(process* p);
void handle_fork(size_t* num_processes, process* p, process* processes[]);
void handle_dup2(char* buf, fd_table* table);
void handle_dup(char* buf, fd_table* table);
void handle_chmod(char* buf, fd_table* table);
void handle_draw(process* p, f_type type, size_t* idx);
void handle_help(char* buf);

/*************
 * MAIN-LOOP
 ************/

int main(void) {
  print_start_message();

  process* processes[MAX_PROCESSES];
  size_t num_processes = 1;
  processes[0] = create_new_process();

  for (size_t i = num_processes; i < MAX_PROCESSES; ++i) {
    processes[i] = NULL;
  }

  char buf[256];
  size_t process_idx = 0;

  printf(">> ");

  while (fgets(buf, sizeof(buf), stdin)) {
    process* p = processes[process_idx];
    fd_table* table = p->table;

    if (buf_contains_prefix(buf, "open")) {
      handle_open(buf, table);
    } else if (buf_contains_prefix(buf, "close")) {
      handle_close(buf, table);
    } else if (buf_contains_prefix(buf, "read")) {
      handle_read(buf, table);
    } else if (buf_contains_prefix(buf, "write")) {
      handle_write(buf, table);
    } else if (buf_contains_prefix(buf, "fseek")) {
      handle_fseek(buf, table);
    } else if (buf_contains_prefix(buf, "pipe list")) {
      handle_pipe_list(p);
    } else if (buf_contains_prefix(buf, "pipe")) {
      handle_pipe(p);
    } else if (buf_contains_prefix(buf, "process switch")) {
      handle_process_switch(buf, &process_idx, processes);
    } else if (buf_contains_prefix(buf, "process list")) {
      handle_process_list(processes);
    } else if (buf_contains_prefix(buf, "process current")) {
      handle_process_current(p);
    } else if (buf_contains_prefix(buf, "process parent")) {
      handle_process_parent(p);
    } else if (buf_contains_prefix(buf, "fork")) {
      handle_fork(&num_processes, p, processes);
    } else if (buf_contains_prefix(buf, "dup2")) {
      handle_dup2(buf, table);
    } else if (buf_contains_prefix(buf, "dup")) {
      // must be after dup2 otherwise always goes there
      handle_dup(buf, table);
    } else if (buf_contains_prefix(buf, "chmod")) {
      handle_chmod(buf, table);
    } else if (buf_contains_prefix(buf, "draw")) {
      // technically not a regular vs pipe but easier impl.
      if (buf_contains_prefix(buf, "draw pipe")) {
        size_t pipe_idx;

        if (sscanf(buf + strlen("draw pipe"), "%zu", &pipe_idx) == 1) {
          handle_draw(p, PIPE, &pipe_idx);
        } else {
          printf("usage: draw pipe <pipe_idx>\n");
        }
      } else {
        handle_draw(p, REGULAR, NULL);
      }
    } else if (buf_contains_prefix(buf, "help")) {
      handle_help(buf);
    } else if (buf_contains_prefix(buf, "quit")) {
      break;
    } else if (buf_contains_prefix(buf, "functions list")) {
      print_functions_list();
    } else {
      print_invalid_command_message();
    }

    printf(">> ");
  }

  for (size_t i = 0; i < num_processes; ++i) {
    process* p = processes[i];
    delete_process(p);
  }

  return 0;
}

/************************
 * FUNCTION DEFINITIONS
 ***********************/

fd_entry* create_fd_entry(char* flags,
                          char* name,
                          f_type file_type,
                          pipe* pipe) {
  fd_entry* entry = malloc(sizeof(fd_entry));

  if (flags == NULL) {
    entry->flags[0] = 'r';
    entry->flags[1] = '-';
    entry->flags[2] = '-';
  } else {
    entry->flags[0] = flags[0];
    entry->flags[1] = flags[1];
    entry->flags[2] = flags[2];
  }
  entry->flags[3] = '\0';

  size_t name_len = strlen(name);
  entry->name = malloc(name_len + 1);
  strcpy(entry->name, name);
  entry->name[name_len] = '\0';

  entry->file_type = file_type;
  entry->ref_count = 1;

  if (file_type == REGULAR) {
    entry->u.offset = 0;
  } else if (file_type == PIPE) {
    entry->u.pipe = pipe;
  } else if (file_type == STD_STREAM) {
    entry->u.stream = NULL;
  }

  return entry;
}

static inline fd_mod fd_mod_offset(size_t offset) {
  fd_mod m;
  m.kind = FD_MOD_OFF;

  m.u.offset = offset;

  return m;
}

static inline fd_mod fd_mod_flags(char r, char w, char x) {
  fd_mod m;
  m.kind = FD_MOD_FLAGS;

  m.u.flags[0] = r;
  m.u.flags[1] = w;
  m.u.flags[2] = x;
  m.u.flags[3] = '\0';

  return m;
}

int modify_fd_entry(fd_entry* entry, fd_mod m) {
  if (entry == NULL) {
    return -1;
  }

  switch (m.kind) {
    case FD_MOD_FLAGS:
      entry->flags[0] = m.u.flags[0];
      entry->flags[1] = m.u.flags[1];
      entry->flags[2] = m.u.flags[2];
      entry->flags[3] = '\0';
      return 0;
    case FD_MOD_OFF:
      entry->u.offset = m.u.offset;
      return 0;
    default:
      return -1;
  }
}

void delete_fd_entry(fd_entry* entry) {
  if (entry == NULL) {
    return;
  }

  free(entry->name);
  entry->name = NULL;

  free(entry);
  entry = NULL;
}

fd_table* create_fd_table(void) {
  fd_table* table = malloc(sizeof(fd_table));

  table->num_files = 3;
  table->size = 8;

  table->files = malloc(table->size * sizeof(fd_entry*));

  table->files[0] = create_fd_entry("r--", "stdin", STD_STREAM, NULL);
  table->files[1] = create_fd_entry("-w-", "stdout", STD_STREAM, NULL);
  table->files[2] = create_fd_entry("-w-", "stderr", STD_STREAM, NULL);

  for (size_t i = 3; i < table->size; ++i) {
    table->files[i] = NULL;
  }

  return table;
}

int modify_fd_table(fd_table* table, size_t idx, fd_mod m) {
  if (idx > table->size) {
    fprintf(stderr, "modify_fd_table: invalid idx");
    return -1;
  }

  return modify_fd_entry(table->files[idx], m);
}

size_t find_free_idx_fd_table(fd_table* table) {
  if (table == NULL) {
    fprintf(stderr, "find_free_idx_fd_table: table is NULL");
  }

  for (size_t i = 0; i < table->size; ++i) {
    if (table->files[i] == NULL) {
      return i;
    }
  }

  fprintf(stderr, "find_free_idx_fd_table: no free indices found");
  return -1;  // dangerous, will wrap around to be very large
}

void fd_table_resize(fd_table* table, size_t new_size) {
  if (table == NULL) {
    return;
  }

  size_t old_size = table->size;

  fd_entry** new_files = malloc(new_size * sizeof(fd_entry*));

  // copy over files into new files
  for (size_t i = 0; i < old_size; ++i) {
    new_files[i] = table->files[i];
  }

  // set all all new files to NULL
  for (size_t i = old_size; i < new_size; ++i) {
    new_files[i] = NULL;
  }

  free(table->files);
  table->size = new_size;
  table->files = new_files;
}

int add_file_fd_table(fd_table* table, fd_entry* entry) {
  if (table == NULL || entry == NULL) {
    fprintf(stderr, "add_file_fd_table: invalid input");
    return -1;
  }

  if (table->num_files < table->size) {
    size_t free_idx = find_free_idx_fd_table(table);
    table->files[free_idx] = entry;
    table->num_files++;
  } else {
    // need to resize array and copy over entries
    size_t old_size = table->size;

    size_t new_size = 2 * old_size;
    fd_table_resize(table, new_size);

    size_t new_num_files = table->num_files + 1;

    // safe assumption that this index is first free index
    table->files[old_size] = entry;

    table->num_files = new_num_files;
  }

  return 0;
}

int close_file_fd_table(fd_table* table, size_t entry_idx) {
  if (table == NULL) {
    fprintf(stderr, "close_file_fd_table: invalid table");
    return -1;
  }

  if (entry_idx >= table->size) {
    fprintf(stderr, " invalid file descriptor");
    return -1;
  }

  fd_entry* entry = table->files[entry_idx];
  if (entry == NULL) {
    fprintf(stderr, "No file with fd %zu\n", entry_idx);
    return 0;
  }

  // theoretically should also resize, halving size but cbb not critical
  table->files[entry_idx] = NULL;

  if (entry->file_type == PIPE) {
    if (str_equal(entry->name, PIPE_READ)) {
      entry->u.pipe->read_open--;
    } else if (str_equal(entry->name, PIPE_WRITE)) {
      entry->u.pipe->write_open--;
    }
  }

  if (entry->ref_count == 1) {
    delete_fd_entry(entry);
    return 0;
  } else {
    entry->ref_count--;
  }

  table->num_files--;

  return 0;
}

fd_table* duplicate_fd_table(fd_table* table) {
  if (table == NULL) {
    fprintf(stderr, "duplicate_fd_table: input is NULL");
    return NULL;
  }

  fd_table* new_table = malloc(sizeof(fd_table));

  new_table->num_files = table->num_files;
  new_table->size = table->size;

  new_table->files = malloc(table->size * sizeof(fd_entry*));

  // copied fd table points to same file as in original table
  for (size_t i = 0; i < table->size; ++i) {
    new_table->files[i] = table->files[i];
    if (new_table->files[i] != NULL) {
      new_table->files[i]->ref_count++;
    }
  }

  return new_table;
}

void delete_fd_table(fd_table* table) {
  if (table == NULL) {
    fprintf(stderr, "delete_fd_table: table is NULL");
    return;
  }

  for (size_t i = 0; i < table->size; ++i) {
    fd_entry* entry = table->files[i];

    if (entry == NULL) {
      continue;
    }

    close_file_fd_table(table, i);
  }

  free(table->files);
  table->files = NULL;
  free(table);
  table = NULL;
}

pipe* create_pipe(void) {
  pipe* ret_pipe = malloc(sizeof(pipe));

  ret_pipe->read_open = 1;
  ret_pipe->write_open = 1;

  return ret_pipe;
}

pipe* duplicate_pipe(pipe* input_pipe) {
  if (input_pipe == NULL) {
    return NULL;
  }

  pipe* new_pipe = malloc(sizeof(pipe));

  new_pipe->read_open = input_pipe->read_open;
  new_pipe->read_open = input_pipe->read_open;

  return new_pipe;
}

void delete_pipe(pipe* pipe) {
  if (pipe == NULL) {
    return;
  }

  free(pipe);
  pipe = NULL;
}

process* create_new_process(void) {
  process* p = malloc(sizeof(process));

  // this is only used for first process, the rest will be children
  // thus pid is 1 and parent is 0 or the shell
  p->pid = 1;
  p->ppid = 0;  // not how os actually does it, just for internal ease

  p->table = create_fd_table();
  for (size_t i = 0; i < MAX_PIPES; ++i) {
    p->process_pipes[i] = NULL;
  }

  return p;
}

process* create_child_process(process* input_p, pid_t pid) {
  if (input_p == NULL) {
    return NULL;
  }

  process* p = malloc(sizeof(process));

  // note: fork returns 0 in child process, but does not set its pid to 0
  p->pid = pid;            // set child pid to "newly generated" pid
  p->ppid = input_p->pid;  // link child to parent

  for (size_t i = 0; i < MAX_PIPES; ++i) {
    pipe* pipe = input_p->process_pipes[i];
    p->process_pipes[i] = duplicate_pipe(pipe);
  }

  p->table = duplicate_fd_table(input_p->table);

  return p;
}

void add_pipe_to_process(process* input_process, pipe* input_pipe) {
  if (input_process == NULL || input_pipe == NULL) {
    return;
  }

  int idx = pipe_idx_available(input_process);
  if (idx == -1) {
    fprintf(stderr, "prcoess has maximum number of pipes\n");
    return;
  }

  input_process->process_pipes[idx] = input_pipe;

  if (input_pipe->read_open) {
    fd_entry* entry = create_fd_entry("r--", PIPE_READ, PIPE, input_pipe);
    add_file_fd_table(input_process->table, entry);
  }

  if (input_pipe->write_open) {
    fd_entry* entry = create_fd_entry("-w-", PIPE_WRITE, PIPE, input_pipe);
    add_file_fd_table(input_process->table, entry);
  }
}

void delete_process(process* p) {
  if (p == NULL) {
    return;
  }

  for (size_t i = 0; i < MAX_PIPES; ++i) {
    pipe* pipe = p->process_pipes[i];
    if (pipe != NULL) {
      delete_pipe(pipe);
    }
  }

  delete_fd_table(p->table);

  free(p);
  p = NULL;
}

static inline int pipe_idx_available(process* p) {
  for (size_t i = 0; i < MAX_PIPES; ++i) {
    if (p->process_pipes[i] == NULL) {
      return i;
    }
  }
  return -1;
}

static inline size_t max(size_t a, size_t b) {
  if (a > b) {
    return a;
  } else {
    return b;
  }
}

static inline int contains_char(char* string, char c) {
  for (size_t i = 0; i < strlen(string); ++i) {
    if (string[i] == c) {
      return 1;
    }
  }

  return 0;
}

static inline int buf_contains_prefix(char* buf, char* str) {
  return (strncmp(buf, str, strlen(str)) == 0);
}

static inline int str_equal(char* str1, char* str2) {
  return strcmp(str1, str2) == 0;
}

static inline size_t digits(size_t x) {
  size_t d = 1;
  while (x >= 10) {
    x /= 10;
    ++d;
  }

  return d;
}

void construct_row(size_t padding,
                   char* buf,
                   size_t buf_size,
                   char* delim,
                   char* col_vals[],
                   size_t desired_col_len[]) {
  size_t off = 0;

  // left delim
  off += snprintf(buf + off, buf_size - off, "%s", delim);

  for (size_t col = 0; col < NUM_COLS; ++col) {
    const char* v = col_vals[col];
    size_t vlen = strlen(v);

    // left padding
    off += snprintf(buf + off, buf_size - off, "%*s", (int)padding, "");

    // value
    off += snprintf(buf + off, buf_size - off, "%s", v);

    // pad to desired col width
    if (desired_col_len[col] > vlen) {
      off += snprintf(buf + off, buf_size - off, "%*s",
                      (int)(desired_col_len[col] - vlen), "");
    }

    // right padding + delim
    off +=
        snprintf(buf + off, buf_size - off, "%*s%s", (int)padding, "", delim);
  }
}

void print_fd_table(fd_table* table) {
  if (table == NULL) {
    return;
  }

  const size_t padding = 1;

  // Column sizes (in characters; assumes simple ASCII content for values)
  size_t max_name = strlen("name");
  size_t max_flags = strlen("flags");
  size_t max_offset = strlen("offset");

  for (size_t i = 0; i < table->size; ++i) {
    fd_entry* entry = table->files[i];
    if (entry == NULL) {
      continue;
    }
    max_name = max(max_name, strlen(entry->name));
    max_offset = max(max_offset, digits(entry->u.offset));
    // flags are fixed-width "rwx" style, so max_flags stays strlen("flags")
  }

  // fd column must fit the largest possible fd index (table->size - 1)
  size_t max_fd = strlen("fd");
  if (table->size > 0) {
    max_fd = max(max_fd, (size_t)snprintf(NULL, 0, "%zu", table->size - 1));
  }

  size_t col_word_len[NUM_COLS] = {max_fd, max_name, max_flags, max_offset};

  size_t total_chars =
      2 + (NUM_COLS - 1) + (2 * padding * NUM_COLS) +
      (col_word_len[0] + col_word_len[1] + col_word_len[2] + col_word_len[3]);

  size_t row_buf_size = total_chars * 8 + 64;

  char* top_line = malloc(row_buf_size);
  char* col_names_line = malloc(row_buf_size);
  char* column_sep_line = malloc(row_buf_size);
  char* bottom_line = malloc(row_buf_size);

  if (!top_line || !col_names_line || !column_sep_line || !bottom_line) {
    fprintf(stderr, "malloc failed\n");
    free(top_line);
    free(col_names_line);
    free(column_sep_line);
    free(bottom_line);
    return;
  }

  size_t off_top = 0, off_mid = 0, off_bot = 0;

  off_top += snprintf(top_line + off_top, row_buf_size - off_top, "┌");
  off_mid += snprintf(column_sep_line + off_mid, row_buf_size - off_mid, "├");
  off_bot += snprintf(bottom_line + off_bot, row_buf_size - off_bot, "└");

  for (size_t col = 0; col < NUM_COLS; ++col) {
    size_t run = 2 * padding + col_word_len[col];

    for (size_t i = 0; i < run; ++i) {
      off_top += snprintf(top_line + off_top, row_buf_size - off_top, "─");
      off_mid +=
          snprintf(column_sep_line + off_mid, row_buf_size - off_mid, "─");
      off_bot += snprintf(bottom_line + off_bot, row_buf_size - off_bot, "─");
    }

    if (col < NUM_COLS - 1) {
      off_top += snprintf(top_line + off_top, row_buf_size - off_top, "┬");
      off_mid +=
          snprintf(column_sep_line + off_mid, row_buf_size - off_mid, "┼");
      off_bot += snprintf(bottom_line + off_bot, row_buf_size - off_bot, "┴");
    }
  }

  off_top += snprintf(top_line + off_top, row_buf_size - off_top, "┐");
  off_mid += snprintf(column_sep_line + off_mid, row_buf_size - off_mid, "┤");
  off_bot += snprintf(bottom_line + off_bot, row_buf_size - off_bot, "┘");

  char* header_vals[NUM_COLS] = {"fd", "name", "flags", "offset"};
  construct_row(padding, col_names_line, row_buf_size, "│", header_vals,
                col_word_len);

  printf("%s\n", top_line);
  printf("%s\n", col_names_line);
  printf("%s\n", column_sep_line);

  // Print each non-NULL entry row
  for (size_t i = 0; i < table->size; ++i) {
    fd_entry* entry = table->files[i];
    if (entry == NULL) {
      continue;
    }

    char* row = malloc(row_buf_size);
    if (!row) {
      break;
    }

    char fd_idx[32];
    snprintf(fd_idx, sizeof(fd_idx), "%zu", i);

    char off_str[32];
    char* off_val = "-";
    if (entry->file_type == REGULAR) {
      snprintf(off_str, sizeof(off_str), "%zu", entry->u.offset);
      off_val = off_str;
    }

    char* vals[NUM_COLS] = {fd_idx, entry->name, entry->flags, off_val};
    construct_row(padding, row, row_buf_size, "│", vals, col_word_len);

    printf("%s\n", row);
    free(row);
  }

  printf("%s\n", bottom_line);

  free(top_line);
  free(col_names_line);
  free(column_sep_line);
  free(bottom_line);
}

void print_pipe(pipe* pipe) {
  // TODO print out the pipes visually, and add description to help message
  if (pipe == NULL) {
    return;
  }
  printf("Read end is: %u\n", pipe->read_open);
  printf("Read end is: %u\n", pipe->write_open);
}

void print_invalid_command_message(void) {
  printf("Invalid command. Retype, or enter 'help'\n");
}

void print_start_message(void) {
  printf(
      "This is a simple program meant to emulate a python interpreter. It "
      "simulates how the OS handles file descriptor tables and pipes across "
      "processes.\nEnter desired function, 'functions list' for list of "
      "accepted "
      "functions, 'help <optional function>' for function description, 'quit' "
      "or EOF to exit.\n");
}

void print_functions_list(void) {
  printf(
      "help, functions list, quit, "
      "open, close, read, write, fseek, "
      "dup, dup2, chmod, "
      "pipe, pipe list, fork, "
      "process current, process list, process switch, process parent, "
      "draw\n");
}

void print_help_message(char* command) {
  char* open_desc =
      "OPEN\n\tusage: open <name> <flags>\n\t<flags> accepts three chars in "
      "order r w "
      "x, "
      "each either the letter or '-'.\n\texamples: rwx, rw-, r--, ---.\n";
  char* close_desc = "CLOSE\n\tusage: close <fd>\n";
  char* read_desc = "READ\n\tusage: read <offset> <fd>\n";
  char* write_desc = "WRITE\n\tusage: write <offset> <fd>\n";
  char* fseek_desc = "FSEEK\n\tusage: fseek <fd> <offset>\n";
  char* pipe_desc = "PIPE\n\tusage: pipe\n";
  char* pipe_list_desc = "PIPE LIST\n\tusage: pipe list\n";
  char* process_switch_desc = "PROCESS SWITCH\n\tusage: process switch <pid>\n";
  char* process_list_desc = "PROCESS LIST\n\tusage: process list\n";
  char* process_current_desc = "PROCESS CURRENT\n\tusage: process current\n";
  char* process_parent_desc = "PROCESS PARENT\n\tusage: process parent\n";
  char* fork_desc = "FORK\n\tusage: fork\n";
  char* dup_desc = "DUP\n\tusage: dup <fd>\n";
  char* dup2_desc = "DUP2\n\tusage: dup2 <oldfd> <newfd>\n";
  char* chmod_desc = "CHMOD\n\tusage: chmod <+/-><perms> <filename>\n";
  char* draw_desc =
      "DRAW\n\tusage: draw <optional pipe> <optional idx>\n\tprints to "
      "terminal either "
      "thethe file "
      "descriptor table or a pipe "
      "of "
      "the "
      "current process\n";
  char* help_desc = "HELP\n\tusage: help <optional command>\n";
  char* quit_desc = "QUIT\n\tusage: quit\n";
  char* functions_list_desc = "FUNCTIONS LIST\n\tusage: functions list\n";

  char* command_descriptions[] = {open_desc,
                                  close_desc,
                                  read_desc,
                                  write_desc,
                                  fseek_desc,
                                  pipe_desc,
                                  pipe_list_desc,
                                  process_switch_desc,
                                  process_list_desc,
                                  process_current_desc,
                                  process_parent_desc,
                                  fork_desc,
                                  dup_desc,
                                  dup2_desc,
                                  chmod_desc,
                                  draw_desc,
                                  help_desc,
                                  quit_desc,
                                  functions_list_desc};

  size_t num_commands =
      sizeof(command_descriptions) / sizeof(command_descriptions[0]);
  if (command == NULL) {
    // print everything out
    printf("Accepted commands:\n");

    for (size_t i = 0; i < num_commands; ++i) {
      printf("%s\n", command_descriptions[i]);
    }
  } else {
    if (buf_contains_prefix(command, "open")) {
      printf("%s", open_desc);
    } else if (buf_contains_prefix(command, "close")) {
      printf("%s", close_desc);
    } else if (buf_contains_prefix(command, "read")) {
      printf("%s", read_desc);
    } else if (buf_contains_prefix(command, "write")) {
      printf("%s", write_desc);
    } else if (buf_contains_prefix(command, "fseek")) {
      printf("%s", fseek_desc);
    } else if (buf_contains_prefix(command, "pipe list")) {
      printf("%s", pipe_list_desc);
    } else if (buf_contains_prefix(command, "pipe")) {
      printf("%s", pipe_desc);
    } else if (buf_contains_prefix(command, "process switch")) {
      printf("%s", process_switch_desc);
    } else if (buf_contains_prefix(command, "process list")) {
      printf("%s", process_list_desc);
    } else if (buf_contains_prefix(command, "process current")) {
      printf("%s", process_current_desc);
    } else if (buf_contains_prefix(command, "process parent")) {
      printf("%s", process_parent_desc);
    } else if (buf_contains_prefix(command, "fork")) {
      printf("%s", fork_desc);
    } else if (buf_contains_prefix(command, "dup")) {
      printf("%s", dup_desc);
    } else if (buf_contains_prefix(command, "dup2")) {
      printf("%s", dup2_desc);
    } else if (buf_contains_prefix(command, "chmod")) {
      printf("%s", chmod_desc);
    } else if (buf_contains_prefix(command, "draw")) {
      printf("%s", draw_desc);
    } else if (buf_contains_prefix(command, "help")) {
      printf("%s", help_desc);
    } else if (buf_contains_prefix(command, "quit")) {
      printf("%s", quit_desc);
    } else if (buf_contains_prefix(command, "functions list")) {
      printf("%s", functions_list_desc);
    }
  }
}

void handle_open(char* buf, fd_table* table) {
  char name[128];
  char flags[4];

  if (sscanf(buf + strlen("open"), "%127s %3s", name, flags) == 2) {
    if (strlen(flags) != 3 || (flags[0] != 'r' && flags[0] != '-') ||
        (flags[1] != 'w' && flags[1] != '-') ||
        (flags[2] != 'x' && flags[2] != '-')) {
      fprintf(stderr,
              "usage: open <name> <flags>\n<flags>: three chars in order r "
              "w x, each either the letter or '-'\nexamples: rwx, rw-, r--, "
              "---\n");
    } else {
      fd_entry* entry = create_fd_entry(flags, name, REGULAR, NULL);
      add_file_fd_table(table, entry);
    }
  } else {
    fprintf(stderr,
            "usage: open <name> <flags>\n<flags>: three chars in order r w x, "
            "each either the letter or '-'\nexamples: rwx, rw-, r--, ---\n");
  }
}

void handle_close(char* buf, fd_table* table) {
  size_t fd;

  if (sscanf(buf + strlen("close"), " %zu", &fd) == 1) {
    close_file_fd_table(table, fd);
  } else {
    fprintf(stderr, "usage: close <fd>\n");
  }
}

void handle_read(char* buf, fd_table* table) {
  size_t offset;
  int fd;

  if (sscanf(buf + strlen("read"), "%zu %d", &offset, &fd) == 2) {
    fd_entry* entry = table->files[fd];

    if (entry == NULL) {
      fprintf(stderr, "Invalid fd\n");
      return;
    }

    if (entry->flags[0] != 'r') {
      fprintf(stderr, "file does not have read perms\n");
      return;
    }

    size_t new_offset = entry->u.offset + offset;
    fd_mod m = fd_mod_offset(new_offset);

    modify_fd_entry(entry, m);
  } else {
    fprintf(stderr, "usage: read <offset> <fd>\n");
  }
}

void handle_write(char* buf, fd_table* table) {
  size_t offset;
  int fd;

  if (sscanf(buf + strlen("write"), "%zu %d", &offset, &fd) == 2) {
    fd_entry* entry = table->files[fd];

    if (entry == NULL) {
      fprintf(stderr, "Invalid fd\n");
      return;
    }

    if (entry->flags[1] != 'w') {
      fprintf(stderr, "file does not have write perms\n");
      return;
    }

    size_t new_offset = entry->u.offset + offset;
    fd_mod m = fd_mod_offset(new_offset);

    modify_fd_entry(entry, m);
  } else {
    fprintf(stderr, "usage: write <offset> <fd>\n");
  }
}

void handle_fseek(char* buf, fd_table* table) {
  size_t offset;
  int fd;

  if (sscanf(buf + strlen("fseek"), "%d %zu", &fd, &offset) == 2) {
    fd_entry* entry = table->files[fd];
    fd_mod m = fd_mod_offset(offset);

    if (entry == NULL) {
      fprintf(stderr, "Invalid fd\n");
      return;
    }

    if (entry->file_type == PIPE || entry->file_type == STD_STREAM) {
      fprintf(stderr, "You cannot call fseek on this type of file\n");
      return;
    }

    if (entry->flags[0] == '-' && entry->flags[1] == '-') {
      fprintf(stderr, "File does not have read or write privileges\n");
      return;
    }

    modify_fd_entry(entry, m);
  } else {
    fprintf(stderr, "usage: fseek <fd> <offset>\n");
  }
}

void handle_pipe(process* p) {
  if (pipe_idx_available(p) == -1) {
    fprintf(stderr, "process has maximum number of pipes\n");
    return;
  } else {
    pipe* pipe = create_pipe();
    add_pipe_to_process(p, pipe);
  }
}

void handle_pipe_list(process* p) {
  if (p == NULL) {
    return;
  }

  int found = 0;

  for (size_t i = 0; i < MAX_PIPES; ++i) {
    pipe* pipe = p->process_pipes[i];
    if (pipe != NULL) {
      printf("Process has a pipe with index %zu\n", i);
      found = 1;
    }
  }

  if (!found) {
    printf("Process has no pipes\n");
  }
}

void handle_process_switch(char* buf,
                           size_t* process_idx,
                           process* processes[]) {
  pid_t pid;

  if (sscanf(buf + strlen("process switch"), "%d", &pid) == 1) {
    // find associated idx, in actuality pid is index into process table,
    // but here pid is unrelated to actual index
    size_t idx = MAX_PROCESSES;

    for (size_t i = 0; i < MAX_PROCESSES; ++i) {
      process* curr_p = processes[i];
      if (curr_p != NULL && curr_p->pid == pid) {
        idx = i;
        break;
      }
    }

    if (idx == MAX_PROCESSES) {
      fprintf(stderr, "There is no process with that pid\n");
    } else {
      *process_idx = idx;
    }
  } else {
    fprintf(stderr, "usage: process switch <pid>\n");
  }
}

void handle_process_list(process* processes[]) {
  for (size_t i = 0; i < MAX_PROCESSES; ++i) {
    process* curr_p = processes[i];
    if (curr_p != NULL) {
      printf("pid: %d\n", curr_p->pid);
    }
  }
}

void handle_process_current(process* p) {
  printf("pid: %d\n", p->pid);
}

void handle_process_parent(process* p) {
  pid_t ppid = p->ppid;
  if (ppid == 0) {
    printf("parent is shell\n");
  } else {
    printf("ppid: %d\n", p->ppid);
  }
}

void handle_fork(size_t* num_processes, process* p, process* processes[]) {
  // important distinction between fork() return value and PIDS. fork() returns
  // 0 in the child and the child's pid in the parent. parent's pid remains
  // unchanged, and child is assigned a newly generated pid (what fork() returns
  // to parent)
  if (*num_processes >= MAX_PROCESSES) {
    fprintf(stderr, "max processes created\n");
  }

  processes[*num_processes] = create_child_process(p, *num_processes + 1);
  *num_processes += 1;
}

void handle_dup2(char* buf, fd_table* table) {
  size_t old_fd;
  size_t new_fd;

  if (sscanf(buf + strlen("dup2"), "%zu %zu", &old_fd, &new_fd) == 2) {
    fd_entry* old_entry = table->files[old_fd];

    if (old_entry == NULL) {
      fprintf(stderr, "Invalid fd\n");
      return;
    }

    // do nothing
    if (old_fd == new_fd) {
      return;
    }

    if (new_fd >= table->size) {
      size_t new_size = new_fd * 2;
      fd_table_resize(table, new_size);
    }

    fd_entry* new_entry = table->files[new_fd];
    if (new_entry != NULL) {
      close_file_fd_table(table, new_fd);
    }

    old_entry->ref_count++;
    if (old_entry->file_type == PIPE) {
      if (str_equal(old_entry->name, PIPE_READ)) {
        old_entry->u.pipe->read_open++;
      } else if (str_equal(old_entry->name, PIPE_WRITE)) {
        old_entry->u.pipe->write_open++;
      }
    }

    table->files[new_fd] = old_entry;
  } else {
    fprintf(stderr, "usage: dup2 <oldfd> <newfd>\n");
  }
}

void handle_dup(char* buf, fd_table* table) {
  size_t fd;

  if (sscanf(buf + strlen("dup"), "%zu", &fd) == 1) {
    fd_entry* entry = table->files[fd];

    if (entry == NULL) {
      fprintf(stderr, "Invalid fd\n");
      return;
    }

    entry->ref_count++;
    if (entry->file_type == PIPE) {
      if (str_equal(entry->name, PIPE_READ)) {
        entry->u.pipe->read_open++;
      } else if (str_equal(entry->name, PIPE_WRITE)) {
        entry->u.pipe->write_open++;
      }
    }

    add_file_fd_table(table, entry);
  } else {
    fprintf(stderr, "usage: dup <fd>\n");
  }
}

void handle_chmod(char* buf, fd_table* table) {
  char add_remove[2];
  char modified_flags[4];
  char filename[64];

  if (sscanf(buf + strlen("chmod"), "%1s%3s %s", add_remove, modified_flags,
             filename) == 3) {
    size_t fd = table->size;

    for (size_t i = 0; i < table->size; ++i) {
      fd_entry* entry = table->files[i];

      if (entry != NULL && str_equal(entry->name, filename)) {
        fd = i;
        break;
      }
    }

    if (fd == table->size) {
      fprintf(stderr, "Invalid fd\n");
      return;
    }

    // already did NULL check in loop
    fd_entry* entry = table->files[fd];

    if (entry->file_type == STD_STREAM) {
      fprintf(stderr, "You cannot call chmod on a standard stream\n");
      return;
    } else if (entry->file_type == PIPE) {
      fprintf(stderr, "You cannot call chmod on a pipe\n");
      return;
    }

    if (!contains_char(modified_flags, 'r') &&
        !contains_char(modified_flags, 'w') &&
        !contains_char(modified_flags, 'x')) {
      fprintf(stderr, "<flags> should be at least one of rwx\n");
      return;
    }

    // some repeat code but whatever
    if (str_equal("+", add_remove)) {
      char r, w, x;
      r = (contains_char(modified_flags, 'r')) ? 'r' : entry->flags[0];
      w = (contains_char(modified_flags, 'w')) ? 'w' : entry->flags[1];
      x = (contains_char(modified_flags, 'x')) ? 'x' : entry->flags[2];

      fd_mod m = fd_mod_flags(r, w, x);
      modify_fd_entry(entry, m);

    } else if (str_equal("-", add_remove)) {
      char r, w, x;
      r = (contains_char(modified_flags, 'r')) ? '-' : entry->flags[0];
      w = (contains_char(modified_flags, 'w')) ? '-' : entry->flags[1];
      x = (contains_char(modified_flags, 'x')) ? '-' : entry->flags[2];

      fd_mod m = fd_mod_flags(r, w, x);
      modify_fd_entry(entry, m);

    } else {
      fprintf(stderr,
              "please enter either '+' to add flags or '-' to remove "
              "flags\n");
      return;
    }
  } else {
    fprintf(stderr, "usage: chmod <+/-><perms> <filename>\n");
  }
}

void handle_draw(process* p, f_type type, size_t* idx) {
  // printing the fd table prints a sort of "merged" process-level FD and
  // system-wide OFT, rather than a pointer for fd entry, it shows what would be
  // seen in the system-wide OFT
  if (type != PIPE) {
    print_fd_table(p->table);
  } else {
    if (*idx >= MAX_PIPES) {
      fprintf(stderr, "this pipe index is out of bounds\n");
      return;
    }

    pipe* pipe = p->process_pipes[*idx];
    if (pipe == NULL) {
      fprintf(stderr, "this process does not have a pipe with index %zu\n",
              *idx);
      return;
    }
    print_pipe(pipe);
  }
}

void handle_help(char* buf) {
  char help_command1[64];

  if (sscanf(buf + strlen("help"), "%s", help_command1) == 1) {
    print_help_message(buf + strlen("help "));
  } else {
    print_help_message(NULL);
  }
}
