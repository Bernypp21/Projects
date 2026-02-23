//Berny Perez, Learning how to use pthread and cypt function in c.
/*
    This program opens files with password and hash and preforms a dictionary attack to crack password.
    main purpose of this assignment is to help me learn about thread and multi threading in my program, as well as you function in c for cryptography.
*/

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <crypt.h>
#include "thread_hash.h"


#ifdef NOISY_DEBUG
# define NOISY_DEBUG_PRINT fprintf(stderr, "%s %s %d\n" \, __FILE__, __func__, __LINE__ )
#else // not NOISY_DEBUG
# define NOISY_DEBUG_PRINT
#endif // NOISY_DEBUG

#define BUF_SIZE 500000

char ** read_data(FILE *,size_t*);
void * do_crypt(void *);
int get_next_row(void);
double elapse_time(struct timeval *, struct timeval *);
hash_algorithm_t algo_pattern(const char *);


//global variables to used for threads
static char ** ifile_lines = NULL;
static char ** dfile_lines = NULL;
static size_t inum = 0;
static size_t dnum = 0;
pthread_mutex_t crack_lock = PTHREAD_MUTEX_INITIALIZER;
int thread_num = 1;
int verbose = 0;
FILE * ofile = NULL;


typedef struct
{
    //counting
    double time;
    //counter
    long algo_counter[ALGORITHM_MAX];
    //number of fails;
    int failed;
    //number of countes
    int cracked;

}stats_info;

stats_info * s_info = NULL;

//function to open and read values from file
char ** read_data(FILE * file, size_t * num_lines)
{
    size_t index = 0;
    char ** data = NULL;
    char buffer[BUF_SIZE] = {0};
    size_t len = 0;
    char ** temp = NULL;

    while(fgets(buffer,BUF_SIZE,file)!= NULL)
    {  
       len = strlen(buffer);
       while(len > 0 && (buffer[len-1] == '\n'))
       {
            buffer[len -1] = '\0';
            len--;
       }
       temp = realloc(data,(index+1)*sizeof(char *));
       if(!temp)
       {
           perror("realloc");
           free(data);
           exit(EXIT_FAILURE);
       }

       data = temp;
       data[index] = strdup(buffer);
       index++;  
    }
    
    *num_lines = index;
    return data;
}

//function that does the decrypting with crypt_rn()
void * do_crypt(void * vid)
{
    size_t i = 0;
    char * crypt_return = NULL;
    struct crypt_data crypt_stuff;
    struct timeval et0;
    struct timeval et1;
    hash_algorithm_t tag = ALGORITHM_MAX;
    long tid = ((long)vid); 

    
   gettimeofday(&et0,NULL);
   for(i = get_next_row(); i < inum; i = get_next_row())
   {

       int cracked = 0;
//       fprintf(stderr, "** %d: >>%s<<\n", __LINE__, ifile_lines[i]);  
       for(size_t j = 0; j < dnum; ++j)
       {
 //          fprintf(stderr, "*** %d: >>%s<< >>%s<<\n", __LINE__, ifile_lines[i], dfile_lines[j]); 


            memset(&crypt_stuff,0,sizeof(crypt_stuff)); 
            crypt_return = crypt_rn(dfile_lines[j],ifile_lines[i],&crypt_stuff,sizeof(crypt_stuff));
            
            if(crypt_return == NULL)
            {
               fprintf (stderr,"something wrong with crypt_rn()");
                exit(EXIT_FAILURE);
            }

            if(strcmp(ifile_lines[i], crypt_return) == 0)
            {
                tag = algo_pattern(ifile_lines[i]);
                fprintf(ofile,"cracked  %s  %s\n ",dfile_lines[j],ifile_lines[i]);
                s_info[tid].cracked++;
                cracked = 1;
                break;                
            }     
            
        }
            if(cracked == 0)
            {
                    fprintf(ofile,"*** failed to crack %s\n", ifile_lines[i]);
                    s_info[tid].failed++;
            }

            s_info[tid].algo_counter[tag]++;    
    }  
     
          
        gettimeofday(&et1,NULL);  
        s_info[tid].time = elapse_time(&et0, &et1); 
        pthread_mutex_lock(&crack_lock);
        fprintf(stderr,"Thread:   %ld     %.2lf sec%13s",tid,s_info[tid].time,"");
        fprintf(stderr,"DES:%4s %ld %13s","",s_info[tid].algo_counter[DES],"");
        fprintf(stderr,"NT:%4s %ld %13s","",s_info[tid].algo_counter[NT],"");
        fprintf(stderr,"MD5:%4s %ld %13s","",s_info[tid].algo_counter[MD5],"");
        fprintf(stderr,"SHA256:%4s %ld %13s","",s_info[tid].algo_counter[SHA256],"");
        fprintf(stderr,"SHA512:%4s %ld %13s","",s_info[tid].algo_counter[SHA512],"");
        fprintf(stderr,"YESCRYPT:%4s %ld %13s","",s_info[tid].algo_counter[YESCRYPT],"");
        fprintf(stderr,"GOS_YESCRYPT:%4s %ld %13s","",s_info[tid].algo_counter[GOST_YESCRYPT],"");
        fprintf(stderr,"BCRYPT:%4s %ld %13s  ","",s_info[tid].algo_counter[BCRYPT],"");
        fprintf(stderr,"Total:      %d  failed:      %d\n",s_info[tid].cracked,s_info[tid].failed);
        pthread_mutex_unlock(&crack_lock);


    pthread_exit(EXIT_SUCCESS);
}


//using mutex to protect data shared by thread
int get_next_row(void)
{
    static int next_row = 0;
    static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    int curr_row = 0;

    //locking resources    
    pthread_mutex_lock(&lock);
    curr_row = next_row++;
    pthread_mutex_unlock(&lock);

    return curr_row;
}


//calculate amount of time passed for process
double elapse_time(struct timeval * t0, struct timeval *t1)
{
   double et;
   //calculating elapsed time
   et = (((double) (t1->tv_usec - t0->tv_usec)) / MICROSECONDS_PER_SECOND) + ((double) (t1->tv_sec - t0->tv_sec));
   return et;
}


hash_algorithm_t algo_pattern(const char * hash)
{

    if(hash[0] != '$')
    {
       return DES;
    }
    if(hash[1] == '3')
    {
       return NT;
    }
    if(hash[1] == '1')
    {
       return MD5;
    }
    if(hash[1] == '5')
    {
       return SHA256;
    }
    if(hash[1] == '6')
    {
       return SHA512;
    }
    if(hash[1] == 'y')
    {
       return YESCRYPT;
    }
    if(hash[1] == 'g')
    {
       return GOST_YESCRYPT;
    }
    if(hash[1] == '2')
    {
       return BCRYPT;
    }
    return ALGORITHM_MAX;
}

int main(int argc, char * argv[])
{
    FILE * ifile = NULL;
    FILE * dfile = NULL;
    pthread_t * threads = NULL;
    long tid = 0;


    //parsing command line
    int opt = 0;
    while((opt = getopt(argc,argv,OPTIONS)) != -1)
    {
        switch(opt)
        {
            case 'i':
                //case for input file
                ifile = fopen(optarg,"r");
               break;
            case 'o':
                //case for output file
                ofile = fopen(optarg, "w");
                if(ofile == NULL)
                { 
                    perror("couldn't open file"); 
                } 
                break;
            case 'd':
                //case for dict
                dfile = fopen(optarg,"r");
               break;
            case 't':
                //case for user thread num
                thread_num = atoi(optarg);
                if(thread_num < 1)
                {
                    thread_num = 1;
                }
                if(thread_num > 24)
                {
                    thread_num = 24;
                }
                break;
            case 'v':
                //case for verbose
                verbose = 1;
                break;
            case 'h':
                //case for help
                printf("help text\n");
                printf(
                 "        %s ...\n"
                 "        Options: i:o:d:hvt:n\n"
                 "                -i file        hash file name (required)\n"
                 "                -o file        output file name (default stdout)\n"
                 "                -d file        dictionary file name (required)\n"
                 "                -t #           number of threads to create (default == 1)\n"
                 "                -n             renice to 10\n"
                 "                -v             enable verbose mode\n"
                 "                -h             helpful text\n",argv[0]);
                    exit(EXIT_SUCCESS);
                    break;
            case 'n':
                //case for break
                if(nice(NICE_VALUE)==-1)
                {
                    perror("invalid nice");
                    exit(EXIT_FAILURE);
                }
                break;
            default:
                printf("No Action given");
                exit(EXIT_FAILURE);
                break;
        }
    }
  
    if(verbose == 1)
    {
        fprintf(stderr,"verbose mode is on\n");
    }
    //checking to see if files open
    if(dfile == NULL)
    {
      fprintf(stderr,"must give name for dictionary input file with -d filename\n");
      exit(EXIT_FAILURE);
    }
    if(ofile == NULL)
    {
        ofile = stdout;
    }

    if(ifile == NULL)
    {
       fprintf(stderr,"must give name for hashed password input file with -i filename\n");
       exit(EXIT_FAILURE);
    }
    
    //reading file into char * arrays
    ifile_lines = read_data(ifile,&inum);
    dfile_lines = read_data(dfile,&dnum);
   
    //create + work for threads
    threads = malloc(thread_num * sizeof(pthread_t));
    s_info = calloc(thread_num ,sizeof(stats_info));


    for(tid = 0; tid < thread_num; tid++)
    {
        pthread_create(&threads[tid],NULL, do_crypt, (void *) tid);
    }
    //join threads
    for(tid = 0; tid < thread_num; tid++)
    {
        pthread_join(threads[tid],NULL);
    }
    //cleaning up
    for(size_t i = 0; i < inum; i++)
    {
        free(ifile_lines[i]);
    }
    free(ifile_lines);
 
    for(size_t i = 0; i < dnum; i++)
    {
        free(dfile_lines[i]);
    } 
    free(dfile_lines);
   

    free(s_info);
    free(threads);
    fclose(ifile);
    fclose(dfile);
       
    if(ofile != stdout)
    {
        fclose(ofile);
    }
    (void)algorithm_string;    
    return EXIT_SUCCESS;
}
