/*****************************************************************************/
/*                       CSC209-24s A4 Audio Stream                          */
/*       Copyright 2024 -- Demetres Kostas PhD (aka Darlene Heliokinde)      */
/*****************************************************************************/
#include "as_client.h"


static int connect_to_server(int port, const char *hostname) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("connect_to_server");
        return -1;
    }

    struct sockaddr_in addr;

    // Allow sockets across machines.
    addr.sin_family = AF_INET;
    // The port the server will be listening on.
    // htons() converts the port number to network byte order.
    // This is the same as the byte order of the big-endian architecture.
    addr.sin_port = htons(port);
    // Clear this field; sin_zero is used for padding for the struct.
    memset(&(addr.sin_zero), 0, 8);

    // Lookup host IP address.
    struct hostent *hp = gethostbyname(hostname);
    if (hp == NULL) {
        ERR_PRINT("Unknown host: %s\n", hostname);
        return -1;
    }

    addr.sin_addr = *((struct in_addr *) hp->h_addr);

    // Request connection to server.
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("connect");
        return -1;
    }

    return sockfd;
}


/*
** Helper for: list_request
** This function reads from the socket until it finds a network newline.
** This is processed as a list response for a single library file,
** of the form:
**                   <index>:<filename>\r\n
**
** returns index on success, -1 on error
** filename is a heap allocated string pointing to the parsed filename
*/
static int get_next_filename(int sockfd, char **filename) {
    static int bytes_in_buffer = 0;
    static char buf[RESPONSE_BUFFER_SIZE];

    while((*filename = find_network_newline(buf, &bytes_in_buffer)) == NULL) {
        int num = read(sockfd, buf + bytes_in_buffer,
                       RESPONSE_BUFFER_SIZE - bytes_in_buffer);
        if (num < 0) {
            perror("list_request");
            return -1;
        }
        bytes_in_buffer += num;
        if (bytes_in_buffer == RESPONSE_BUFFER_SIZE) {
            ERR_PRINT("Response buffer filled without finding file\n");
            ERR_PRINT("Bleeding data, this shouldn't happen, but not giving up\n");
            memmove(buf, buf + BUFFER_BLEED_OFF, RESPONSE_BUFFER_SIZE - BUFFER_BLEED_OFF);
        }
    }

    char *parse_ptr = strtok(*filename, ":");
    int index = strtol(parse_ptr, NULL, 10);
    parse_ptr = strtok(NULL, ":");
    // moves the filename to the start of the string (overwriting the index)
    memmove(*filename, parse_ptr, strlen(parse_ptr) + 1);

    return index;
}

// COMPLETE
int list_request(int sockfd, Library *library) {
    // Send the LIST command to the server
    const char *list_command = "LIST\r\n";
    if (write(sockfd, list_command, strlen(list_command)) < 0){
        perror("list_request: write");
        return -1;
    }
    // Initialize or reset the library
    _free_library(library);
    // Read and print the list of files
    char * filename = NULL;
    int max = 0;
    int index = 0;
    int count = 0;
    char *buffer[MAX_FILES];
    while ((index = get_next_filename(sockfd, &filename)) > -1) {
        max = (index > max) ? index : max;
        // Allocate memory for the new files array with an extra slot for the new filename
        library->files = realloc(library->files, (count + 1) * sizeof(char *));
        if (!library->files) {
            perror("realloc");
            _free_library(library);  // Free any allocated memory
            return -1;
        }

        // Add the new filename to the library
        buffer[count] = filename;  // filename is already allocated by get_next_filename
        count++;
        if (count > max){
            break;
        }
    }
    if (index == -1){ // Error checking
        perror("list_request: index");
        return -1;
    }
    library->num_files = count;
    
    for (int i = 0; i < count; i++) {
        library->files[i] = buffer[count - i - 1];
        printf("%d: %s\n", i, library->files[i]);
    }

    // If get_next_filename returned -1 due to an error (not just EOF)
    // if (errno != 0) {
    //     perror("get_next_filename");
    //     _free_library(library);  // Free any allocated memory
    //     return -1;
    // }

    return count;
}

// COMPLETE 
/*
** Get the permission of the library directory. If the library 
** directory does not exist, this function shall create it.
**
** library_dir: the path of the directory storing the audio files
** perpt:       an output parameter for storing the permission of the 
**              library directory.
**
** returns 0 on success, -1 on error
*/
static int get_library_dir_permission(const char *library_dir, mode_t * perpt) {
    struct stat st;
    int result = stat(library_dir, &st);
    
    if (result == 0) {
        // Directory exists, retrieve the permissions
        *perpt = st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
        return 0;
    } else if (errno == ENOENT) {
        // Directory does not exist, try to create it
        mode_t mode = 0700;
        result = mkdir(library_dir, mode);
        if (result == 0) {
            *perpt = mode;
            return 0;
        } else {
            // Handle error in mkdir
            perror("mkdir");
            return -1;
        }
    } else {
        // Handle errors in stat
        perror("stat");
        return -1;
    }
}

/*
** Creates any directories needed within the library dir so that the file can be
** written to the correct destination. All directories will inherit the permissions
** of the library_dir.
**
** This function is recursive, and will create all directories needed to reach the
** file in destination.
**
** Destination shall be a path without a leading /
**
** library_dir can be an absolute or relative path, and can optionally end with a '/'
**
*/
static void create_missing_directories(const char *destination, const char *library_dir) {
    // get the permissions of the library dir
    mode_t permissions;
    if (get_library_dir_permission(library_dir, &permissions) == -1) {
        exit(1);
    }

    char *str_de_tokville = strdup(destination);
    if (str_de_tokville == NULL) {
        perror("create_missing_directories");
        return;
    }

    char *before_filename = strrchr(str_de_tokville, '/');
    if (!before_filename){
        goto free_tokville;
    }

    char *path = malloc(strlen(library_dir) + strlen(destination) + 2);
    if (path == NULL) {
        goto free_tokville;
    } *path = '\0';

    char *dir = strtok(str_de_tokville, "/");
    if (dir == NULL){
        goto free_path;
    }
    strcpy(path, library_dir);
    if (path[strlen(path) - 1] != '/') {
        strcat(path, "/");
    }
    strcat(path, dir);

    while (dir != NULL && dir != before_filename + 1) {
        #ifdef DEBUG
        printf("Creating directory %s\n", path);
        #endif
        if (mkdir(path, permissions) == -1) {
            if (errno != EEXIST) {
                perror("create_missing_directories");
                goto free_path;
            }
        }
        dir = strtok(NULL, "/");
        if (dir != NULL) {
            strcat(path, "/");
            strcat(path, dir);
        }
    }
free_path:
    free(path);
free_tokville:
    free(str_de_tokville);
}


/*
** Helper for: get_file_request
*/
static int file_index_to_fd(uint32_t file_index, const Library * library){
    create_missing_directories(library->files[file_index], library->path);

    char *filepath = _join_path(library->path, library->files[file_index]);
    if (filepath == NULL) {
        return -1;
    }

    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    #ifdef DEBUG
    printf("Opened file %s\n", filepath);
    #endif
    free(filepath);
    if (fd < 0 ) {
        perror("file_index_to_fd");
        return -1;
    }

    return fd;
}


int get_file_request(int sockfd, uint32_t file_index, const Library * library){
    #ifdef DEBUG
    printf("Getting file %s\n", library->files[file_index]);
    #endif

    int file_dest_fd = file_index_to_fd(file_index, library);
    if (file_dest_fd == -1) {
        return -1;
    }

    int result = send_and_process_stream_request(sockfd, file_index, -1, file_dest_fd);
    if (result == -1) {
        return -1;
    }

    return 0;
}

// COMPLETE
int start_audio_player_process(int *audio_out_fd) {
    // Hint: Use these two lines so that path is looked up
    // char *args[] = AUDIO_PLAYER_ARGS;
    // execvp(AUDIO_PLAYER, args);
    // return -1;

    int pipefd[2];
    
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return -1;
    }

    pid_t pid = fork();
    
    if (pid == -1) {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    } else if (pid == 0) {  // Child process
        close(pipefd[1]);  // Close the write end

        if (dup2(pipefd[0], STDIN_FILENO) == -1) {
            perror("dup2");
            return -1;
        }
        close(pipefd[0]);  // Close the original file descriptor

        // Replace this process with the audio player process
        char *args[] = AUDIO_PLAYER_ARGS;
        execvp(AUDIO_PLAYER, args);
        // exec only returns if there is an error
        perror("execvp");        
        exit(1);
    }

    // Parent process
    close(pipefd[0]);  // Close the read end, parent won't use this
    sleep(AUDIO_PLAYER_BOOT_DELAY);

    // Give the write end of the pipe to the caller
    *audio_out_fd = pipefd[1];
    // Return the child's PID
    return pid;
}


static void _wait_on_audio_player(int audio_player_pid) {
    int status;
    if (waitpid(audio_player_pid, &status, 0) == -1) {
        perror("_wait_on_audio_player");
        return;
    }
    if (WIFEXITED(status)) {
        fprintf(stderr, "Audio player exited with status %d\n", WEXITSTATUS(status));
    } else {
        printf("Audio player exited abnormally\n");
    }
}


int stream_request(int sockfd, uint32_t file_index) {
    int audio_out_fd;
    int audio_player_pid = start_audio_player_process(&audio_out_fd);
    int result = send_and_process_stream_request(sockfd, file_index, audio_out_fd, -1);
    if (result == -1) {
        ERR_PRINT("stream_request: send_and_process_stream_request failed\n");
        return -1;
    }

    _wait_on_audio_player(audio_player_pid);

    return 0;
}


int stream_and_get_request(int sockfd, uint32_t file_index, const Library * library) {
    int audio_out_fd;
    int audio_player_pid = start_audio_player_process(&audio_out_fd);

    #ifdef DEBUG
    printf("Getting file %s\n", library->files[file_index]);
    #endif

    int file_dest_fd = file_index_to_fd(file_index, library);
    if (file_dest_fd == -1) {
        ERR_PRINT("stream_and_get_request: file_index_to_fd failed\n");
        return -1;
    }

    int result = send_and_process_stream_request(sockfd, file_index,
                                                 audio_out_fd, file_dest_fd);
    if (result == -1) {
        ERR_PRINT("stream_and_get_request: send_and_process_stream_request failed\n");
        return -1;
    }
    _wait_on_audio_player(audio_player_pid);

    return 0;
}



// COMPLETE
int _write_to_buffer(char **source, char **dest, int bytes_to_write, int current_size){
    // source - to copy to dest
    // dest - dynamically sized buffer of size current_size
    // bytes_to_write - size of source
    if ((current_size + bytes_to_write) < 0){
        perror("_write_to_buffer: realloc size");
        return -1;
    }
    char* temp = (char*)realloc(*dest, current_size + bytes_to_write);
    if (temp == NULL) {
        perror("Realloc");
        return -1;
    }
    *dest = temp;
    if (bytes_to_write > 0) {
        memset(*dest + current_size, 0, bytes_to_write); // set all bytes after the current size to 0
    }
    
    // Copy the content from the source to the destination buffer.
    memcpy(*dest + current_size, *source, bytes_to_write); // copy over from the end of the list, the new bytes

    memset(*source, 0, bytes_to_write); // reset the fixed_array to uninitalized data

    return bytes_to_write; // Success
}

int _remove_from_buffer(char **buffer, int bytes_to_remove, int buffer_size){
    memmove(*buffer, *buffer + bytes_to_remove, (buffer_size - bytes_to_remove));
    // Adjust the buffer size.
    int new_buffer_size = buffer_size - bytes_to_remove;
    char *tempBuffer = (char *)realloc(*buffer, new_buffer_size);
    if (tempBuffer == NULL) {
        // Failed to reallocate memory.
        return -1;
    }

    *buffer = tempBuffer;
    return bytes_to_remove;
}

int _remove_from_buffer_temp(char **buffer, int bytes_to_remove, int buffer_size){
    // Create a temporary buffer on the stack.
    char tempBuffer[buffer_size];

    // Copy the content we want to keep to the temporary buffer.
    memcpy(tempBuffer, *buffer + bytes_to_remove, buffer_size - bytes_to_remove);

    // Reallocate the dynamic buffer to the new size.
    int new_buffer_size = buffer_size - bytes_to_remove;
    char *newBuffer = (char *)realloc(*buffer, new_buffer_size);
    if (newBuffer == NULL) {
        // Failed to reallocate memory.
        return -1;
    }

    // Copy the content back from the temporary buffer to the reallocated buffer.
    memcpy(newBuffer, tempBuffer, new_buffer_size);

    // Update the buffer pointer.
    *buffer = newBuffer;

    return bytes_to_remove;
}

// COMPLETE
/*
** Sends a stream request for the particular file_index to the server and sends the audio
** stream to the audio_out_fd and file_dest_fd file descriptors
** -- provided that they are not < 0.
**
** The select system call should be used to simultaneously wait for data to be available
** to read from the server connection/socket, as well as for when audio_out_fd and file_dest_fd
** (if applicable) are ready to be written to. Differing numbers of bytes may be written to
** at each time (do no use write_precisely for this purpose -- you will nor receive full marks)
** audio_out_fd and file_dest_fd, and this must be handled.
**
** One of audio_out_fd or file_dest_fd can be -1, but not both. File descriptors >= 0
** should be closed before the function returns.
**
** This function will leverage a dynamic circular buffer with two output streams
** and one input stream. The input stream is the server connection/socket, and the output
** streams are audio_out_fd and file_dest_fd. The buffer should be dynamically sized using
** realloc. See the assignment handout for more information, and notice how realloc is used
** to manage the library.files in this client and the server.
**
** Phrased differently, this uses a FIFO with two independent out streams and one in stream,
** but because it is as long as needed, we call it circular, and just point to three different
** parts of it.
**
** returns 0 on success, -1 on error
*/
int send_and_process_stream_request(int sockfd, uint32_t file_index, int audio_out_fd, int file_dest_fd) {
    
    char *stream_command = "STREAM\r\n"; // first part of the request
    if (write_precisely(sockfd, stream_command, strlen(stream_command)) < 0){
        perror("send_and_process_stream_request: write");
        return -1;
    }

    uint32_t net_file_index = htonl(file_index);
    if (write_precisely(sockfd, &net_file_index, sizeof(net_file_index)) < 0){
        perror("send_and_process_stream_request: write");
        return -1;
    }
    size_t init_buffer_size = INITIAL_BUFFER_SIZE;
    size_t read_buffer_size = NETWORK_PRE_DYNAMIC_BUFF_SIZE;
    char *fixed_buffer = (char *)calloc(read_buffer_size, sizeof(char)); // malloc(read_buffer_size); // For data from server
    char *dynamic_buffer = (char *)calloc(INITIAL_BUFFER_SIZE, sizeof(char)); // malloc(init_buffer_size); // For data to audio/file
    if (!fixed_buffer || !dynamic_buffer) {
        perror("send_and_process_stream_request: calloc");
    }
    int current_buffer_size = init_buffer_size;
    int total_bytes_removed = 0;
    
    // Byte tracking
    int total_bytes_read = 0; // total bytes read from the function
    int total_bytes_to_read = 0; // i.e. filesize, starts at 4 because first four bytes containing file_size not included
    int write_audio_total = 0; // total bytes written to audio fd 
    int write_file_total = 0; // total bytes written to file fd 
    
    // Timeout arg for select
    struct timeval timeout;
    timeout.tv_sec = SELECT_TIMEOUT_SEC;
    timeout.tv_usec = SELECT_TIMEOUT_USEC;

    // Init fd_sets
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    FD_SET(sockfd, &read_fds); // set read fd
    
    int numfd; // get max fd
    if ((file_dest_fd > audio_out_fd) && (file_dest_fd > sockfd)){
        numfd = file_dest_fd + 1;
    } else if ((audio_out_fd > file_dest_fd) && (audio_out_fd > sockfd)){
        numfd = audio_out_fd + 1;
    } else {
        numfd = sockfd + 1;
    }

    while (1) {
        // Nothing to write on the first loop, so no need to set fds until we get first four bytes
        // Sets write_fds once data is available
        fd_set read_fds_copy, write_fds_copy;
        read_fds_copy = read_fds;
        write_fds_copy = write_fds;


        if (select(numfd, &read_fds_copy, &write_fds_copy, NULL, &timeout) < 1){
            perror("select"); 
            return -1;
        }
        
        // If read fd is ready
        if (FD_ISSET(sockfd, &read_fds_copy)) {
            // Get first 4 bytes / first read
            if (total_bytes_read == 0){

                char file_size[4] = {0};
                if (read(sockfd, file_size, 4) != 4){
                    perror("send_and_process_stream_request: reading file size");
                    return -1;
                }
                uint8_t total_bytes_in_file[4]; 
                memcpy(total_bytes_in_file, file_size, 4);
                total_bytes_to_read += ntohl(*((int *)total_bytes_in_file));
                                                                             
                // Write the first 4 bytes to the file
                // int write_buf = _write_to_buffer(&fixed_buffer, &dynamic_buffer, 4, current_buffer_size);
                // // Write fixed_buffer data into dynamic_buffer with realloc memory of bytes_read
                // if (write_buf < 0){
                //     perror("_write_to_buffer");
                //     free(fixed_buffer);
                //     free(dynamic_buffer);
                //     return -1;
                // };
                // current_buffer_size += write_buf;
                // total_bytes_read += write_buf;
                // if (total_bytes_read >= total_bytes_to_read){ // If finished reading

                //     if (total_bytes_read > total_bytes_to_read){
                //         printf("Got more bytes than expected\n");
                //     }
                // }
            }
            
            // Read data from socket up to read_buffer_size
            int bytes_read = read(sockfd, fixed_buffer, read_buffer_size);
            if (bytes_read < 0){
                perror("read");
                free(fixed_buffer);
                free(dynamic_buffer);
                return -1;
            }
            
            if ((total_bytes_read + bytes_read) > total_bytes_to_read){ // If new sum is greater than the amount of bytes expected
                // printf("\n Bytes read before buffer: %d/%d\n", (total_bytes_read + bytes_read), total_bytes_to_read);
                printf("Got more bytes than expected\n");
                int overflow = total_bytes_read - total_bytes_to_read; // Get how much we overflow by
                bytes_read -= overflow; // New value for bytes to be passed to the fixed_buffer.
            }
            
            total_bytes_read += bytes_read;

            int write_buf = _write_to_buffer(&fixed_buffer, &dynamic_buffer, bytes_read, current_buffer_size);
            // Write fixed_buffer data into dynamic_buffer with realloc memory of bytes_read
            if (write_buf < 0){
                perror("_write_to_buffer");
                free(fixed_buffer);
                free(dynamic_buffer);
                return -1;
            };
            current_buffer_size += write_buf;

            if (total_bytes_read >= total_bytes_to_read){ // If finished reading
            } else { // Add back to set and set write fds too
                
                FD_SET(sockfd, &read_fds); // Add it back to the set
                if (audio_out_fd >= 0) FD_SET(audio_out_fd, &write_fds);
                if (file_dest_fd >= 0) FD_SET(file_dest_fd, &write_fds);
            }

            
        }

        // if write fd for file is ready
        if (file_dest_fd != -1){
            if (FD_ISSET(file_dest_fd, &write_fds_copy)) {
                int bytes_wrote = write(file_dest_fd, dynamic_buffer + 1, current_buffer_size-1);
                if (bytes_wrote < 0){
                    perror("write");
                    return -1;
                }
                write_file_total += bytes_wrote;

                
                if (audio_out_fd == -1){ // if only file writing
                    // remove data from buffer, only writing once, so bytes_wrote always what to remove
                    int removed_data = _remove_from_buffer(&dynamic_buffer, bytes_wrote, current_buffer_size);
                    if (removed_data < 0){ 
                        perror("_remove_from_buffer");
                        return -1;
                    }
                    current_buffer_size -= removed_data;
                    total_bytes_removed += removed_data;
                } else if (audio_out_fd != -1 && (write_file_total <= write_audio_total)){ // if doing both
                    
                    // Calculate bytes to remove
                    int bytes_to_remove;
                    if (write_file_total < write_audio_total) {
                        bytes_to_remove = write_file_total - total_bytes_removed;
                    } else {
                        bytes_to_remove = write_audio_total - total_bytes_removed;
                    }
                    
                    // remove data from buffer
                    int removed_data = _remove_from_buffer(&dynamic_buffer, bytes_to_remove, current_buffer_size);
                    if (removed_data < 0){ 
                        perror("_remove_from_buffer: reallocate");
                        return -1;
                    }
                    current_buffer_size -= removed_data;
                    total_bytes_removed += removed_data;
                }

                if (total_bytes_removed == total_bytes_to_read){ // If fully cleaned the buffer
                    break;
                }
                
                if (current_buffer_size > 1){
                    FD_SET(file_dest_fd, &write_fds);
                }
            }
        }
        // if write fd for audio is ready
        if (audio_out_fd != -1) {
            if (FD_ISSET(audio_out_fd, &write_fds_copy)) {            
                int bytes_wrote = write(audio_out_fd, dynamic_buffer + 1, current_buffer_size-1);
                if (bytes_wrote < 0){
                    perror("write");
                    return -1;
                }
                write_audio_total += bytes_wrote;
                

                if (file_dest_fd == -1){ // If file_dest_fd closed i.e. not saving
                    int removed_data = _remove_from_buffer(&dynamic_buffer, bytes_wrote, current_buffer_size);
                    if (removed_data < 0){ 
                        perror("_remove_from_buffer");
                        return -1;
                    }
                    current_buffer_size -= removed_data;
                    total_bytes_removed += removed_data;
                } else if (file_dest_fd != -1 && (write_audio_total <= write_file_total)) {
                    int bytes_to_remove;
                    if (write_file_total < write_audio_total) {
                        bytes_to_remove = write_file_total - total_bytes_removed;
                    } else {
                        bytes_to_remove = write_audio_total - total_bytes_removed;
                    }
                    int removed_data = _remove_from_buffer(&dynamic_buffer, bytes_to_remove, current_buffer_size);
                    if (removed_data < 0){ 
                        perror("_remove_from_buffer: reallocate");
                        return -1;
                    }
                    current_buffer_size -= removed_data;
                    total_bytes_removed += removed_data;
                }
                
                if (total_bytes_removed == total_bytes_to_read){
                    break;
                }
                
                if (current_buffer_size > 1) {
                    FD_SET(audio_out_fd, &write_fds);
                }
            }
            
        }

    }

    // Close file descriptors
    if (audio_out_fd >= 0) close(audio_out_fd);
    if (file_dest_fd >= 0) close(file_dest_fd);

    free(fixed_buffer);
    free(dynamic_buffer);
    return 0; // SUCCESS
}



static void _print_shell_help(){
    printf("Commands:\n");
    printf("  list: List the files in the library\n");
    printf("  get <file_index>: Get a file from the library\n");
    printf("  stream <file_index>: Stream a file from the library (without saving it)\n");
    printf("  stream+ <file_index>: Stream a file from the library\n");
    printf("                        and save it to the local library\n");
    printf("  help: Display this help message\n");
    printf("  quit: Quit the client\n");
}


/*
** Shell to handle the client options
** ----------------------------------
** This function is a mini shell to handle the client options. It prompts the
** user for a command and then calls the appropriate function to handle the
** command. The user can enter the following commands:
** - "list" to list the files in the library
** - "get <file_index>" to get a file from the library
** - "stream <file_index>" to stream a file from the library (without saving it)
** - "stream+ <file_index>" to stream a file from the library and save it to the local library
** - "help" to display the help message
** - "quit" to quit the client
*/
static int client_shell(int sockfd, const char *library_directory) {
    char buffer[REQUEST_BUFFER_SIZE];
    char *command;
    int file_index;

    Library library = {"client", library_directory, NULL, 0};

    while (1) {
        if (library.files == 0) {
            printf("Server library is empty or not retrieved yet\n");
        }

        printf("Enter a command: ");
        if (fgets(buffer, REQUEST_BUFFER_SIZE, stdin) == NULL) {
            perror("client_shell");
            goto error;
        }

        command = strtok(buffer, " \n");
        if (command == NULL) {
            continue;
        }

        // List Request -- list the files in the library
        if (strcmp(command, CMD_LIST) == 0) {
            if (list_request(sockfd, &library) == -1) {
                goto error;
            }


        // Get Request -- get a file from the library
        } else if (strcmp(command, CMD_GET) == 0) {
            char *file_index_str = strtok(NULL, " \n");
            if (file_index_str == NULL) {
                printf("Usage: get <file_index>\n");
                continue;
            }
            file_index = strtol(file_index_str, NULL, 10);
            if (file_index < 0 || file_index >= library.num_files) {
                printf("Invalid file index\n");
                continue;
            }

            if (get_file_request(sockfd, file_index, &library) == -1) {
                goto error;
            }

        // Stream Request -- stream a file from the library (without saving it)
        } else if (strcmp(command, CMD_STREAM) == 0) {
            char *file_index_str = strtok(NULL, " \n");
            if (file_index_str == NULL) {
                printf("Usage: stream <file_index>\n");
                continue;
            }
            file_index = strtol(file_index_str, NULL, 10);
            if (file_index < 0 || file_index >= library.num_files) {
                printf("Invalid file index\n");
                continue;
            }

            if (stream_request(sockfd, file_index) == -1) {
                goto error;
            }

        // Stream and Get Request -- stream a file from the library and save it to the local library
        } else if (strcmp(command, CMD_STREAM_AND_GET) == 0) {
            char *file_index_str = strtok(NULL, " \n");
            if (file_index_str == NULL) {
                printf("Usage: stream+ <file_index>\n");
                continue;
            }
            file_index = strtol(file_index_str, NULL, 10);
            if (file_index < 0 || file_index >= library.num_files) {
                printf("Invalid file index\n");
                continue;
            }

            if (stream_and_get_request(sockfd, file_index, &library) == -1) {
                goto error;
            }

        } else if (strcmp(command, CMD_HELP) == 0) {
            _print_shell_help();

        } else if (strcmp(command, CMD_QUIT) == 0) {
            printf("Quitting shell\n");
            break;

        } else {
            printf("Invalid command\n");
        }
    }

    _free_library(&library);
    return 0;
error:
    _free_library(&library);
    return -1;
}


static void print_usage() {
    printf("Usage: as_client [-h] [-a NETWORK_ADDRESS] [-p PORT] [-l LIBRARY_DIRECTORY]\n");
    printf("  -h: Print this help message\n");
    printf("  -a NETWORK_ADDRESS: Connect to server at NETWORK_ADDRESS (default 'localhost')\n");
    printf("  -p  Port to listen on (default: " XSTR(DEFAULT_PORT) ")\n");
    printf("  -l LIBRARY_DIRECTORY: Use LIBRARY_DIRECTORY as the library directory (default 'as-library')\n");
}


int main(int argc, char * const *argv) {
    int opt;
    int port = DEFAULT_PORT;
    const char *hostname = "localhost";
    const char *library_directory = "saved";

    while ((opt = getopt(argc, argv, "ha:p:l:")) != -1) {
        switch (opt) {
            case 'h':
                print_usage();
                return 0;
            case 'a':
                hostname = optarg;
                break;
            case 'p':
                port = strtol(optarg, NULL, 10);
                if (port < 0 || port > 65535) {
                    ERR_PRINT("Invalid port number %d\n", port);
                    return 1;
                }
                break;
            case 'l':
                library_directory = optarg;
                break;
            default:
                print_usage();
                return 1;
        }
    }

    printf("Connecting to server at %s:%d, using library in %s\n",
           hostname, port, library_directory);

    int sockfd = connect_to_server(port, hostname);
    if (sockfd == -1) {
        return -1;
    }

    int result = client_shell(sockfd, library_directory);
    if (result == -1) {
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}
