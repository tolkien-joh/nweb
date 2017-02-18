#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define VERSION 24
#define BUFSIZE 8096
#define DEFAULT_PORT  "8081"
#define WARN       41
#define ERROR      42
#define LOG        44
#define FORBIDDEN 403
#define NOTFOUND  404

#ifndef SIGCLD
#   define SIGCLD SIGCHLD
#endif

static struct {
  char *ext;
  char *filetype;
} extensions [] = {
  {"gif", "image/gif" },
  {"jpg", "image/jpg" },
  {"jpeg","image/jpeg"},
  {"png", "image/png" },
  {"ico", "image/ico" },
  {"zip", "image/zip" },
  {"gz",  "image/gz"  },
  {"tar", "image/tar" },
  {"htm", "text/html" },
  {"html","text/html" },
  {0,0} };
static char *bin_type = "application/octet-stream";

static void logger(int type, char *s1, char *s2, int socket_fd)
{
  int fd ;
  char logbuffer[BUFSIZE*2];

  switch (type) {
  case WARN: (void)sprintf(logbuffer,"WARNING: %s:%s Errno=%d exiting pid=%d",s1, s2, errno, getpid());
    break;
  case ERROR: (void)sprintf(logbuffer,"ERROR: %s:%s Errno=%d exiting pid=%d",s1, s2, errno, getpid());
    break;
  case FORBIDDEN:
    (void)write(socket_fd, "HTTP/1.1 403 Forbidden\nContent-Length: 185\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>403 Forbidden</title>\n</head><body>\n<h1>Forbidden</h1>\nThe requested URL, file type or operation is not allowed on this simple static file webserver.\n</body></html>\n",271);
    (void)sprintf(logbuffer,"FORBIDDEN: %s:%s",s1, s2);
    break;
  case NOTFOUND:
    (void)write(socket_fd, "HTTP/1.1 404 Not Found\nContent-Length: 136\nConnection: close\nContent-Type: text/html\n\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\nThe requested URL was not found on this server.\n</body></html>\n",224);
    (void)sprintf(logbuffer,"NOT FOUND: %s:%s",s1, s2);
    break;
  case LOG: (void)sprintf(logbuffer," INFO: %s:%s:%d",s1, s2,socket_fd); break;
  }
  /* No checks here, nothing can be done with a failure anyway */
  if((fd = open("nweb.log", O_CREAT| O_WRONLY | O_APPEND,0644)) >= 0) {
    (void)write(fd,logbuffer,strlen(logbuffer));
    (void)write(fd,"\n",1);
    (void)close(fd);
  }
  if(type == ERROR || type == NOTFOUND || type == FORBIDDEN) exit(3);
}

/*
 * http://beej.us/guide/bgnet/output/html/multipage/getaddrinfoman.html
   code for a server waiting for connections
   namely a stream socket on port "port", on this host's IP
   either IPv4 or IPv6.
*/ 
static int start_server(char *port) {
  int listenfd, rv;
  struct addrinfo hints, *servinfo, *p;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE; // use my IP address

  if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
    logger(ERROR, "getaddrinfo", (char *)gai_strerror(rv), 0);
  }

  // loop through all the results and bind to the first we can
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((listenfd = socket(p->ai_family, p->ai_socktype,
            p->ai_protocol)) == -1) {
        logger(WARN, "socket", strerror(errno), 0);
        continue;
    }

    if (bind(listenfd, p->ai_addr, p->ai_addrlen) == -1) {
        close(listenfd);
        logger(WARN, "bind", strerror(errno), 0);
        continue;
    }

    break; // if we get here, we must have connected successfully
  }

  if (p == NULL) {
    // looped off the end of the list with no successful bind
    logger(ERROR, "failed to bind socket", strerror(errno), 0);
  }

  freeaddrinfo(servinfo); // all done with this structure

  return listenfd;
}

/* this is a child web server process, so we can exit on errors */
static void web(int fd, int hit)
{
  int j, file_fd, buflen;
  long i, ret, len;
  char * fstr;
  static char buffer[BUFSIZE+1]; /* static so zero filled */

  ret =read(fd,buffer,BUFSIZE);   /* read Web request in one go */
  if(ret == 0 || ret == -1) {  /* read failure stop now */
    logger(FORBIDDEN,"failed to read browser request","",fd);
  }
  if(ret > 0 && ret < BUFSIZE)  /* return code is valid chars */
    buffer[ret]=0;    /* terminate the buffer */
  else buffer[0]=0;
  for(i=0;i<ret;i++)  /* remove CF and LF characters */
    if(buffer[i] == '\r' || buffer[i] == '\n')
      buffer[i]='*';
  logger(LOG,"request",buffer,hit);
  if( strncmp(buffer,"GET ",4) && strncmp(buffer,"get ",4) ) {
    logger(FORBIDDEN,"Only simple GET operation supported",buffer,fd);
  }
  for(i=4;i<BUFSIZE;i++) { /* null terminate after the second space to ignore extra stuff */
    if(buffer[i] == ' ') { /* string is "GET URL " +lots of other stuff */
      buffer[i] = 0;
      break;
    }
  }
  for(j=0;j<i-1;j++)   /* check for illegal parent directory use .. */
    if(buffer[j] == '.' && buffer[j+1] == '.') {
      logger(FORBIDDEN,"Parent directory (..) path names not supported",buffer,fd);
    }
  if( !strncmp(&buffer[0],"GET /\0",6) || !strncmp(&buffer[0],"get /\0",6) ) /* convert no filename to index file */
    (void)strcpy(buffer,"GET /index.html");

  /* work out the file type and check we support it */
  buflen=strlen(buffer);
  fstr = (char *)0;
  for(i=0;extensions[i].ext != 0;i++) {
    len = strlen(extensions[i].ext);
    if( !strncmp(&buffer[buflen-len], extensions[i].ext, len)) {
      fstr =extensions[i].filetype;
      break;
    }
  }
  if(fstr == 0) fstr = bin_type;

  if(( file_fd = open(&buffer[5],O_RDONLY)) == -1) {  /* open the file for reading */
    logger(NOTFOUND, "failed to open file",&buffer[5],fd);
  }
  logger(LOG,"SEND",&buffer[5],hit);
  len = (long)lseek(file_fd, (off_t)0, SEEK_END); /* lseek to the file end to find the length */
        (void)lseek(file_fd, (off_t)0, SEEK_SET); /* lseek back to the file start ready for reading */
          (void)sprintf(buffer,"HTTP/1.1 200 OK\nServer: nweb/%d.0\nContent-Length: %ld\nConnection: close\nContent-Type: %s\n\n", VERSION, len, fstr); /* Header + a blank line */
  logger(LOG,"Header",buffer,hit);
  (void)write(fd,buffer,strlen(buffer));

  /* send file in 8KB block - last block may be smaller */
  while (  (ret = read(file_fd, buffer, BUFSIZE)) > 0 ) {
    (void)write(fd,buffer,ret);
  }
  sleep(1);  /* allow socket to drain before signalling the socket is closed */
  close(fd);
  exit(1);
}

static void usage(void) {
  (void)printf("usage: nweb [option]\t\t\t\tversion %d\n\n"
  "\tnweb is a small and very safe mini web server\n"
  "\tThere is no fancy features = safe and secure.\n\n"
  "\t-h\t\tdisplay this message\n"
  "\t-p number\tweb port number (default: %s)\n"
  "\t-r directory\troot_directory (default: %s)\n"
  "\t-d\t\trun in background\n"
  , VERSION, DEFAULT_PORT, getenv("PWD"));

  (void)printf("\n\tNot Supported: URLs including \"..\", Java, Javascript, CGI\n"
  "\tNot Supported: directories / /etc /bin /lib /tmp /usr /dev /sbin \n"
  "\tNo warranty given or implied\n"
  "\t\t\t\t\tYong-iL Joh jsjjsmith888@gmail.com\n"  );

  exit(0);
}

int main(int argc, char **argv)
{
  int i, pid, listenfd, socketfd, hit;
  char *port;
  socklen_t length;
  static struct sockaddr_in cli_addr; /* static = initialised to zeros */
  static struct sockaddr_in serv_addr; /* static = initialised to zeros */
  char c;
  int _daemonize = 0;

  port = DEFAULT_PORT;
  //Parsing the command line arguments
  while ((c = getopt (argc, argv, "hp:r:d")) != -1) {
    switch (c) {
      case 'r':
        if( !strncmp(optarg,"/"   ,2 ) || !strncmp(optarg,"/etc", 5 ) ||
            !strncmp(optarg,"/bin",5 ) || !strncmp(optarg,"/lib", 5 ) ||
            !strncmp(optarg,"/tmp",5 ) || !strncmp(optarg,"/usr", 5 ) ||
            !strncmp(optarg,"/dev",5 ) || !strncmp(optarg,"/sbin",6) ){
          (void)printf("ERROR: Bad top directory %s, see nweb -h\n",optarg);
          exit(3);
        }
        if(chdir(optarg) == -1) {
          (void)printf("ERROR: Can't Change to directory %s\n",optarg);
          exit(4);
        }
        break;
      case 'p':
        port = optarg;
        i = atoi(port);
        if(i < 0 || i > 60000) {
          logger(ERROR,"Invalid port number (try 1->60000)",optarg,0);
        }
        break;
      case 'd':
        _daemonize = 1;
        break;
      case 'h':
      default:
        usage();
    }
  }

  /* Become deamon + unstopable and no zombies children (= no wait()) */
  if (_daemonize) {
    if(fork() != 0)
      return 0; /* parent returns OK to shell */
    (void)signal(SIGCLD, SIG_IGN); /* ignore child death */
    (void)signal(SIGHUP, SIG_IGN); /* ignore terminal hangups */
   for(i=0;i<32;i++)
      (void)close(i);    /* close open files */
    (void)setpgrp();    /* break away from process group */
  }
  logger(LOG,"nweb starting",argv[1],getpid());

  /* setup the network socket */
  listenfd = start_server(port);
  if (listenfd < 0)
    return -1;

  if( listen(listenfd,64) <0)
    logger(ERROR,"system call","listen",0);
  for(hit=1; ;hit++) {
    length = sizeof(cli_addr);
    if((socketfd = accept(listenfd, (struct sockaddr *)&cli_addr, &length)) < 0)
      logger(ERROR,"system call","accept",0);
    if((pid = fork()) < 0) {
      logger(ERROR,"system call","fork",0);
    } else {
      if(pid == 0) {   /* child */
        (void)close(listenfd);
        web(socketfd,hit); /* never returns */
      } else {   /* parent */
        (void)close(socketfd);
      }
    }
  }
}
